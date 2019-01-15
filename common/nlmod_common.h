#ifndef __NLMOD_COMMON__
#define __NLMOD_COMMON__

enum nlmod_attr_type {
    NLMODULE_UNDEF,
    NLMODULE_STR,
    NLMODULE_U32,
    __NLMODULE_MAX,
};

enum nlmod_cmd {
    NLMODULE_GET_STR,
    NLMODULE_SET_STR,
    NLMODULE_GET_INT,
    NLMODULE_SET_INT,
};

/*struct nlmod_hdr {
    union {
        struct {
            uint16_t type;
            uint16_t len;
        };
        uint16_t hdr;
    };
};*/

#define NLMOD_CUSTOM_NAME "NLMOD_CUSTOM"
#define NLMODULE_MAX (__NLMODULE_MAX - 1)
/*#define NLMODULE_HDR_SIZE sizeof(struct nlmod_hdr)
*/
#endif