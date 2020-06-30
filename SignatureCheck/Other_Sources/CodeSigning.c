#include "CodeSigning.h"
#include <stdio.h>
#include <string.h>
#import <CommonCrypto/CommonDigest.h>

// 코드가 왠지 hash 비교만 있을거 같다.. signature check말고..=> 역시.. ㅋㅋㅋ hash 만 비교.. => 이경우는 re-signing되면 우회될거 같음. 

// page 의 hash 구해서 codedirectory의 hash랑 비교해 보는 함수.. 
// 근데 내가 필요한건 이게 아니긴한데.. 
unsigned char validateSlot(const void *data, size_t length, size_t slot, const CS_CodeDirectory *codeDirectory)
{
    uint8_t digest[CC_SHA1_DIGEST_LENGTH + 1] = {0, }; // 그냥 stack 변수로 잡았네.. 
    CC_SHA1(data, (CC_LONG)length, digest); // data/legnth가 page 단위 일듯.. sha1 해서 digeeset에 저장.
    // 아래는 sha-1값을 비교하는 부분. base+offset 그리고 slot은 index 20은 sha-1 hash size 저장된거. 
    return (memcmp(digest, (void *)((char *)codeDirectory + ntohl(codeDirectory->hashOffset) + 20*slot), 20) == 0);
}

//아래가 핵심. 
//binaryContent : mach-o format 말함.. 이건 file에 대한 거. ( image의 경우 dladdr로 header 바로 받음.. )
void checkCodeSignature(void *binaryContent){
    struct load_command *machoCmd;
    const struct mach_header *machoHeader;

    machoHeader = (const struct mach_header *) binaryContent;

    // fat 파일 나누기.. (image였다면 이게 필요 없지)
    if(machoHeader->magic == FAT_CIGAM){
        unsigned int offset = 0;
        struct fat_arch *fatArch = (struct fat_arch *)((struct fat_header *)machoHeader + 1);
        struct fat_header *fatHeader = (struct fat_header *)machoHeader;
        for(uint32_t i = 0; i < ntohl(fatHeader->nfat_arch); i++)
        {
            if(sizeof(int *) == 4 && !(ntohl(fatArch->cputype) & CPU_ARCH_ABI64)) // check 32bit section for 32bit architecture
            {
                offset = ntohl(fatArch->offset);
                break;
            }
            else if(sizeof(int *) == 8 && (ntohl(fatArch->cputype) & CPU_ARCH_ABI64)) // and 64bit section for 64bit architecture
            {
                offset = ntohl(fatArch->offset);
                break;
            }
            fatArch = (struct fat_arch *)((uint8_t *)fatArch + sizeof(struct fat_arch));
        }
        // 헤더 선택해서 교체 하네.. ( cpu architecture에 맞춰서.)
        machoHeader = (const struct mach_header *)((uint8_t *)machoHeader + offset);
    }




    // 32bit 일때
    if(machoHeader->magic == MH_MAGIC)    // 32bit
    {
        machoCmd = (struct load_command *)((struct mach_header *)machoHeader + 1); // +1하면 다음 mach_header 위치인데(없는거) 이위치 
    																			   // typecast로.. 진행. 
    }
    else if(machoHeader->magic == MH_MAGIC_64)   // 64bit
    {
        machoCmd = (struct load_command *)((struct mach_header_64 *)machoHeader + 1);
    }
    // 여기까지 loadcommand 시작 위치 check. 


    // load command 있을때.
    for(uint32_t i=0; i < machoHeader->ncmds && machoCmd != NULL; i++){
    	// 시그니처 일때 . 
        if(machoCmd->cmd == LC_CODE_SIGNATURE)
        {
        	// linkedit_data_command로 parsing 해야 하나봄. signature loadcommand는.. 
            struct linkedit_data_command *codeSigCmd = (struct linkedit_data_command *) machoCmd;

            // header위치 부터 offset 만큼  떨어진 곳은 superblob
            const CS_SuperBlob *codeEmbedded = (const CS_SuperBlob *)&((char *)machoHeader)[codeSigCmd->dataoff];
            void *binaryBase = (void *)machoHeader;

            const CS_BlobIndex curIndex = codeEmbedded->index[0]; // 이건 codedirecxtory가 100% 확실 한가봄..
                                                                  // 참고로 codedirecotyr[0]이 legacy?

            // 아래는 codedirectory0 특정.
            const CS_CodeDirectory *codeDirectory = (const CS_CodeDirectory *)((char *)codeEmbedded + ntohl(curIndex.offset));

            size_t pageSize = codeDirectory->pageSize ? (1 << codeDirectory->pageSize) : 0; 
            // ?1을 천번 shift? why? 이부분 오류 같음.. 아마 0x1000 쓰인 그대로가 맞을듯.. 0이면 애기는 다르고.. >> nop 이게 맞았음.. 
            // 근데 왜 이게 맞는건지.. 까먹었네..;; 할튼 1000% 이게 맞았는데.. 
            // https://opensource.apple.com/source/libsecurity_codesigning/libsecurity_codesigning-55032/lib/StaticCode.cpp
            //https://opensource.apple.com/source/libsecurity_codesigning/libsecurity_codesigning-55032/lib/codedirectory.cpp.auto.html

            size_t remaining = ntohl(codeDirectory->codeLimit);
            size_t processed = 0;
            for(size_t slot = 0; slot < ntohl(codeDirectory->nCodeSlots); ++slot){
                size_t size = MIN(remaining, pageSize);
                if(!validateSlot(binaryBase+processed, size, slot, codeDirectory)){
                    return;
                }
                processed += size;
                remaining -= size;
            }
            printf("[*] Code is valid!");
        }

        // 뭐냐 이건.. for문안에 있어야 할거 같은데.. 
    	machoCmd = (struct load_command *)((uint8_t *)machoCmd + machoCmd->cmdsize);
    }

    
}
