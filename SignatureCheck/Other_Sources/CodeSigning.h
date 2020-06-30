// stackover에더 띠온것.
// https://stackoverflow.com/questions/29598313/checking-code-integrity-in-ios?rq=1

#ifndef CodeSigning_h
#define CodeSigning_h

#include <stdio.h>

// codes from https://opensource.apple.com/source/Security/Security-55179.1/libsecurity_codesigning/lib/cscdefs.h
// 아.. 이거 blob type인거 같다.. ( 근데 이 구조체는 superblob이랑 blob둘다 가능한건가? => ㅇㅇ 같이씀.)

enum {
    CSMAGIC_REQUIREMENT = 0xfade0c00,       /* single Requirement blob */
    CSMAGIC_REQUIREMENTS = 0xfade0c01,      /* Requirements vector (internal requirements) */
    CSMAGIC_CODEDIRECTORY = 0xfade0c02,     /* CodeDirectory blob */
    CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0, /* embedded form of signature data */ // superblob에서 쓰임. 
    CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1, /* multi-arch collection of embedded signatures */

    CSSLOT_CODEDIRECTORY = 0,               /* slot index for CodeDirectory */
};
/*
 * Structure of an embedded-signature SuperBlob
 */
typedef struct __BlobIndex {
    uint32_t type;                  /* type of entry */
    uint32_t offset;                /* offset of entry */
} CS_BlobIndex;

typedef struct __SuperBlob {
    uint32_t magic;                 /* magic number */
    uint32_t length;                /* total length of SuperBlob */
    uint32_t count;                 /* number of index entries following */
    CS_BlobIndex index[];           /* (count) entries */
    /* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;


/*
 * C form of a CodeDirectory.
 */
typedef struct __CodeDirectory {
    uint32_t magic;                 /* magic number (CSMAGIC_CODEDIRECTORY) */
    uint32_t length;                /* total length of CodeDirectory blob */ // 여기 까지가 CS_blob.. 
    uint32_t version;               /* compatibility version */
    uint32_t flags;                 /* setup and mode flags */
    uint32_t hashOffset;            /* offset of hash slot element at index zero */ // 이거 codehash index0 가리킴 ( special 말고)
    uint32_t identOffset;           /* offset of identifier string */
    uint32_t nSpecialSlots;         /* number of special hash slots */
    uint32_t nCodeSlots;            /* number of ordinary (code) hash slots */
    uint32_t codeLimit;             /* limit to main image signature range */
    uint8_t hashSize;               /* size of each hash in bytes */
    uint8_t hashType;               /* type of hash (cdHashType* constants) */
    uint8_t spare1;                 /* unused (must be zero) */
    uint8_t pageSize;               /* log2(page size in bytes); 0 => infinite */
    uint32_t spare2;                /* unused (must be zero) */
    /* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory;


/*
CS_SuperBlob : Mach-o에 loadcommand -> codesignature(superblob 위치) // 각각의 blob을 가리키는 blob index array 존재 
즉, 아래 내용은 codedirectory blob 찾는내용일듯. ( parsing을 위해 CS_CodeDirectory 형태로 받기도 했고..  )

뭐냐.. 이거 안쓰네.. 
보통 index 0가 codedirectory 인듯.
*/
static inline const CS_CodeDirectory *findCodeDirectory(const CS_SuperBlob *embedded)
{
    // ntohl : big->little ( 이거 사실 htonl 같은거 써도 되는거 아닌가.. 맞는듯..  )
    // 여튼 magic은 big endian 으로 file에 들어가 있고 -> int로 읽었을경우 h이니까 n으로 변경하는게 맞는듯.. 원래는..
    if (embedded && ntohl(embedded->magic) == CSMAGIC_EMBEDDED_SIGNATURE) {

        const CS_BlobIndex *limit = &embedded->index[ntohl(embedded->count)]; // limit를 주소로 체크 하는듯.  
        const CS_BlobIndex *p; // 현재 blob ( type으로 판단하고 offset을 return 일듯.)

        // 맞네. 
        for (p = embedded->index; p < limit; ++p)
            if (ntohl(p->type) == CSSLOT_CODEDIRECTORY) {
                const unsigned char *base = (const unsigned char *)embedded; // base+offset 계산은 이렇게 하는거지. 
                const CS_CodeDirectory *cd = (const CS_CodeDirectory *)(base + ntohl(p->offset));
                if (ntohl(cd->magic) == CSMAGIC_CODEDIRECTORY){
                    return cd;
                }
                else{
                    break;
                }
            }

    }
    // not found
    return NULL;
}

//
unsigned char validateSlot(const void *data, size_t length, size_t slot, const CS_CodeDirectory *codeDirectory);
#endif /* CodeSigning_h */
