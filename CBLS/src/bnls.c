/*
 * bnls.c
 *
 *  Created on: Oct 1, 2009
 *      Author: Scott
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "bnls.h"
#include "bnls_warden.h"
#include "debug.h"
#include "bncsutil.h"
#include "xmalloc.h"

extern void cbls_log (const char *fmt, ...);

char *
gamestr(int prod) {
    switch(prod) {
    case PRODUCT_STAR: return "STAR";
    case PRODUCT_SEXP: return "SEXP";
    case PRODUCT_W2BN: return "W2BN";
    case PRODUCT_D2DV: return "D2DV";
    case PRODUCT_D2XP: return "D2XP";
    case PRODUCT_JSTR: return "JSTR";
    case PRODUCT_WAR3: return "WAR3";
    case PRODUCT_W3XP: return "W3XP";
    case PRODUCT_DRTL: return "DRTL";
    case PRODUCT_DSHR: return "DSHR";
    case PRODUCT_SSHR: return "SSHR";
    default:
        return 0;
    }
}

typedef struct {
    uint32_t client_token;
    uint32_t server_token;
    char *cdkey;
    uint8_t success;
    uint32_t hash[9];
} key_hash_t;

void key_hash(key_hash_t *key) {
    uint32_t *d_keylen = &key->hash[0];
    uint32_t *d_prod = &key->hash[1];
    uint32_t *d_pub = &key->hash[2];
    uint32_t *d_unused = &key->hash[3];
    char *d_buf = (char*)&key->hash[4];

    key->success = !kd_quick(key->cdkey, key->client_token, key->server_token,
            d_pub, d_prod, d_buf, 20);

    if(key->success) {
        // Success
        *d_keylen = strlen(key->cdkey);
        *d_unused = 0;
    } else {
        // Failure
        memset(key->hash, 0, 36);
    }
}

typedef struct {
    uint32_t ver_byte;
    char *f_game;
    char *f_snp;
    char *f_storm;
    char *f_img;
} hash_files_t;

static hash_files_t *hash_files = 0;

hash_files_t*
get_hashes(uint32_t prod) {
    if((prod < PRODUCT_FIRST) || (prod > PRODUCT_LAST))
        return 0;

    if(!hash_files) {
        int length = (PRODUCT_LAST - PRODUCT_FIRST) * sizeof(hash_files_t);
        hash_files = xmalloc(length);
        memset(hash_files, 0, length);
    }

    hash_files_t *prod_hashes = &hash_files[prod-PRODUCT_FIRST];
    if(prod_hashes->f_game)
        return prod_hashes;

    char prefix[11];
    strcpy(prefix, "IX86/");
    strcat(prefix, gamestr(prod));
    strcat(prefix, "/");

    char files_txt[20];
    strcpy(files_txt, prefix);
    strcat(files_txt, "Files.txt");

    FILE *ftxt = fopen(files_txt, "r");
    if(ftxt == NULL) {
        cbls_log("Couldn't open %s", files_txt);
        exit(1);
    }

    /* Grab the version byte off the first line */
    if(fscanf(ftxt, "0x%X\n", &prod_hashes->ver_byte) < 1) {
        cbls_log("Couldn't find version byte in %s", files_txt);
        exit(1);
    }

    char temp[128];
    strcpy(temp, prefix);
    if(fscanf(ftxt, "%s\n", &temp[10]) < 1) {
        cbls_log("Couldn't find game.exe filename in %s", files_txt);
        exit(1);
    }
    prod_hashes->f_game = strdup(temp);
    if(fscanf(ftxt, "%s\n", &temp[10]) < 1) {
        cbls_log("Couldn't find storm.dll filename in %s", files_txt);
        exit(1);
    }
    prod_hashes->f_storm = strdup(temp);
    if(fscanf(ftxt, "%s\n", &temp[10]) < 1) {
        cbls_log("Couldn't find battle.snp filename in %s", files_txt);
        exit(1);
    }
    prod_hashes->f_snp = strdup(temp);
    if(fscanf(ftxt, "%s", &temp[10]) >= 1)
        prod_hashes->f_img = strdup(temp);

    fclose(ftxt);
    return prod_hashes;
}

void
bnls_null(struct packet_reader *pr) {
    // keep-alive
    cbls_log("[%u] BNLS_NULL", pr->cbls->uid);
}

void
bnls_cdkey(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD)  Server Token
     * (STRING) CD-Key, no dashes or spaces
     */
    key_hash_t key;
    memset(&key_hash, 0, sizeof(key_hash_t));

    if(!read_dword(pr, &key.server_token)
    || !(key.cdkey = read_string(pr))) {
        cbls_close(cbls);
        return;
    }

    /***/
    cbls_log("[%u] BNLS_CDKEY %s", cbls->uid, key.cdkey);
    key_hash(&key);

    /**
     * (BOOLEAN)  Result
     * (DWORD)    Client Token
     * (DWORD[9]) CD key data for SID_AUTH_CHECK
     */
    struct packet_writer pw;
    write_init(&pw, cbls, BNLS_CDKEY, 44);
    write_dword(&pw, key.success);
    write_dword(&pw, key.client_token);
    write_raw(&pw, key.hash, 36);
    write_end(&pw);
}

void
bnls_logonchallenge(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (STRING) Account Name
     * (STRING) Password
     */
    char *account_name, *account_pass;

    if(!(account_name = read_string(pr))
    || !(account_pass = read_string(pr))) {
        cbls_close(cbls);
        return;
    }

    /***/
    cbls_log("[%u] BNLS_LOGONCHALLENGE %s %s", cbls->uid, account_name, account_pass);
    char var_a[32];

    if (cbls->nls)
        nls_free(cbls->nls);
    cbls->nls = nls_init(account_name, account_pass);
    if(!cbls->nls) {
        cbls_log("[%u] nls_init() failed", cbls->uid);
        cbls_close(cbls);
        return;
    }
    nls_get_A(cbls->nls, var_a);

    /**
     * (DWORD[8]) Data for SID_AUTH_ACCOUNTLOGON
     */
    struct packet_writer pw;
    write_init(&pw, cbls, BNLS_LOGONCHALLENGE, 32);
    write_raw(&pw, var_a, 32);
    write_end(&pw);
}

void
bnls_logonproof(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD[16]) Data from SID_AUTH_ACCOUNTLOGON
     */
    char salt[32], var_b[32];

    if(!read_raw(pr, salt, 32)
    || !read_raw(pr, var_b, 32)) {
        cbls_close(cbls);
        return;
    }

    /***/
    cbls_log("[%u] BNLS_LOGONPROOF", cbls->uid);
    char M1[20];

    if(!cbls->nls) {
        cbls_log("[%u] nls_get_M1() NLS uninitialized", cbls->uid);
        cbls_close(cbls);
        return;
    }
    nls_get_M1(cbls->nls, M1, var_b, salt);

    /**
     * (DWORD[5]) Data for SID_AUTH_ACCOUNTLOGONPROOF
     */
    struct packet_writer pw;
    write_init(&pw, cbls, BNLS_LOGONPROOF, 20);
    write_raw(&pw, M1, 20);
    write_end(&pw);
}

void
bnls_createaccount(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (STRING) Account Name
     * (STRING) Password
     */
    char *account_name, *account_pass;

    if(!(account_name = read_string(pr))
    || !(account_pass = read_string(pr))) {
        cbls_close(cbls);
        return;
    }

    /***/
    cbls_log("[%u] BNLS_CREATEACCOUNT %s %s", cbls->uid, account_name, account_pass);
    char result[97]; // 64 bytes for result, 32 for username, one for null

    if(cbls->nls)
        nls_free(cbls->nls);
    cbls->nls = nls_init(account_name, account_pass);
    if(!cbls->nls) {
        cbls_log("[%u] nls_init() failed", cbls->uid);
        cbls_close(cbls);
        return;
    }
    if(!nls_account_create(cbls->nls, result, 97)) {
        cbls_log("[%u] nls_account_create() failed", cbls->uid);
        cbls_close(cbls);
        return;
    }

    /**
     * (DWORD[16]) Data for SID_AUTH_ACCOUNTCREATE
     */
    struct packet_writer pw;
    write_init(&pw, cbls, BNLS_CREATEACCOUNT, 64);
    write_raw(&pw, result, 64);
    write_end(&pw);
}

void
bnls_changechallenge(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (STRING) Account Name
     * (STRING) Account's Old Password
     * (STRING) Account's New Password
     */
    char *account_name, *account_old_pass, *account_new_pass;

    if(!(account_name = read_string(pr))
    || !(account_old_pass = read_string(pr))
    || !(account_new_pass = read_string(pr))) {
        cbls_close(cbls);
        return;
    }

    /***/
    cbls_log("[%u] BNLS_CHANGECHALLENGE %s %s %s", cbls->uid, account_name, account_old_pass, account_new_pass);
    char var_a[32];
    if(cbls->nls)
        nls_free(cbls->nls);
    cbls->nls = nls_init(account_name, account_old_pass);
    if(!cbls->nls) {
        cbls_log("[%u] nls_init() failed", cbls->uid);
        cbls_close(cbls);
        return;
    }
    nls_get_A(cbls->nls, var_a);
    cbls->new_password = xstrdup(account_new_pass);

    /**
     * (DWORD[8]) Data for SID_AUTH_ACCOUNTCHANGE
     */
    struct packet_writer pw;
    write_init(&pw, cbls, BNLS_CHANGECHALLENGE, 32);
    write_raw(&pw, var_a, 32);
    write_end(&pw);
}

void
bnls_changeproof(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD[16]) Data from SID_AUTH_ACCOUNTCHANGE
     */
    char salt[32], server_key[32];

    if(!read_raw(pr, salt, 32)
    || !read_raw(pr, server_key, 32)) {
        cbls_close(cbls);
        return;
    }

    /***/
    cbls_log("[%u] BNLS_CHANGEPROOF", cbls->uid);
    char *result;

    if(!cbls->nls) {
        cbls_log("[%u] NLS not initialized", cbls->uid);
        cbls_close(cbls);
        return;
    }
    if(!cbls->new_password) {
        cbls_log("[%u] new password not initialized", cbls->uid);
        cbls_close(cbls);
        return;
    }
    nls_t *old_nls = cbls->nls;
    cbls->nls = nls_account_change_proof(old_nls, result, cbls->new_password, server_key, salt);
    nls_free(old_nls);
    if(!cbls->nls) {
        cbls_log("[%u] nls_account_change_proof() failed", cbls->uid);
        cbls_close(cbls);
        return;
    }

    /**
     * (DWORD[21]) Data for SID_AUTH_ACCOUNTCHANGEPROOF
     */
    struct packet_writer pw;
    write_init(&pw, cbls, BNLS_CHANGEPROOF, 84);
    write_raw(&pw, result, 84);
    write_end(&pw);
}

void
bnls_upgradechallenge(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (STRING) Account Name
     * (STRING) Account's Old Password
     * (STRING) Account's New Password (May be identical to old password, but still must be provided.) WHOEVER THOUGHT OF THIS PACKET SPEC IS RETARDED
     */
    char *account_name, *account_old_pass, *account_new_pass;

    if(!(account_name = read_string(pr))
    || !(account_old_pass = read_string(pr))
    || !(account_new_pass = read_string(pr))) {
        cbls_close(cbls);
        return;
    }

    /***/
    cbls_log("[%u] BNLS_UPGRADECHALLENGE %s %s %s", cbls->uid, account_name, account_old_pass, account_new_pass);
    if(cbls->nls)
        nls_free(cbls->nls);
    cbls->nls = nls_init(account_name, account_old_pass);
    if(!cbls->nls) {
        cbls_log("[%u] BNLS_UPGRADECHALLENGE: nls_init() failed to initialize", cbls->uid);
        cbls_close(cbls);
        return;
    }

    /**
     * (BOOLEAN) Success code
     */
    struct packet_writer pw;
    write_init(&pw, cbls, BNLS_UPGRADECHALLENGE, 4);
    write_dword(&pw, 1);
    write_end(&pw);
}

void
bnls_upgradeproof(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD)    Client Token
     * (DWORD[5]) Old Password Hash
     * (DWORD[8]) New Password Salt
     * (DWORD[8]) New Password Verifier
     */
    uint32_t client_token;
    uint32_t old_pw_hash[5], new_pw_salt[8], new_pw_verifier[8];

    if(!read_dword(pr, &client_token)
    || !read_raw(pr, old_pw_hash, 20)
    || !read_raw(pr, new_pw_salt, 32)
    || !read_raw(pr, new_pw_verifier, 32)) {
        cbls_close(cbls);
        return;
    }

    /***/
    cbls_log("[%u] BNLS_UPGRADEPROOF unimplemented", cbls->uid);
    cbls_close(cbls);
    return;

    /**
     * (DWORD[22]) Data for SID_AUTH_ACCOUNTUPGRADEPROOF
     */
}

void
bnls_versioncheck(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD)  Product ID
     * (DWORD)  Version DLL digit in the range 0-7 (For example, for IX86Ver1.mpq, the digit is 1)
     * (STRING) Checksum Formula
     */
    uint32_t product_id, version_dll;
    char *checksum_formula;

    if(!read_dword(pr, &product_id)
    || !read_dword(pr, &version_dll)
    || !(checksum_formula = read_string(pr)))
    {
        cbls_close(cbls);
        return;
    }

    /***/
    cbls_log("[%u] BNLS_VERSIONCHECK %s %u", cbls->uid, gamestr(product_id), version_dll);
    uint32_t success, version, checksum;
    hash_files_t *hashes;
    char statstr[128];

    memset(statstr, 0, 128);
    success = 0;

    hashes = get_hashes(product_id);

    if(hashes && hashes->f_game) {
        /* if(hashes->f_img) */
        if((product_id == PRODUCT_STAR)
        || (product_id == PRODUCT_SEXP)
        || (product_id == PRODUCT_W2BN)) {
            char lockdownfile[32];
            snprintf(lockdownfile, 32, "IX86/lockdown-IX86-%u.dll", version_dll);
            success = ldCheckRevision(hashes->f_game, hashes->f_storm, hashes->f_snp, checksum_formula,
                    &version, &checksum, statstr,
                    lockdownfile, hashes->f_img);
            if(!success)
                cbls_log("[%u] ldCheckRevision() failed!", cbls->uid);
            else
                success = strlen(statstr);
        } else {
            if(version_dll >= 0) {
                success = checkRevisionFlat(
                        checksum_formula, hashes->f_game, hashes->f_storm, hashes->f_snp, version_dll, &checksum);
                if(success) {
                    success = getExeInfo(
                            hashes->f_game, statstr, 128, &version, BNCSUTIL_PLATFORM_X86);
                    if(!success)
                        cbls_log("[%u] getExeInfo() failed", cbls->uid);
                } else {
                    cbls_log("[%u] checkRevision() failed", cbls->uid);
                }
            } else {
                cbls_log("[%u] BNLS_VERSIONCHECK: bad mpqnumber", cbls->uid, version_dll);
            }
        }
    }

    /**
     * (BOOLEAN) Success
     *
     * If Success is TRUE:
     * (DWORD)  Version
     * (DWORD)  Checksum
     * (STRING) Version check stat string
     */
    struct packet_writer pw;
    // success contains strlen(statstr)
    write_init(&pw, cbls, BNLS_VERSIONCHECK, (success == 0) ? 8 : 21 + success);
    write_dword(&pw, !!success);
    if(success > 0) {
        write_dword(&pw, version);
        write_dword(&pw, checksum);
        write_string(&pw, statstr);
    }
    write_end(&pw);
}

void
bnls_confirmlogon(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD[5]) Password proof from Battle.net
     */

    /***/
    cbls_log("[%u] BNLS_CONFIRMLOGON unimplemented", cbls->uid);
    cbls_close(cbls);
    return;

    /**
     * (BOOLEAN) Success
     */
}

void
bnls_hashdata(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD) The size of the data to be hashed. Note: This is no longer restricted to 64 bytes.
     * (DWORD) Flags
     * (VOID)  Data to be hashed.
     *
     * Optional Data:
     * (DWORD) Client key. Present only if HASHDATA_FLAG_DOUBLEHASH (0x02) is specified.
     * (DWORD) Server key. Present only if HASHDATA_FLAG_DOUBLEHASH (0x02) is specified.
     * (DWORD) Cookie. Present only if HASHDATA_FLAG_COOKIE (0x04) is specified.
     */
    uint32_t data_len;
    uint32_t flags;
    void *data;
    uint32_t client_key;
    uint32_t server_key;
    uint32_t cookie;

    if(!read_dword(pr, &data_len)
    || !read_dword(pr, &flags)
    || !(data = read_void(pr, data_len))) {
        cbls_close(cbls);
        return;
    }

    if(flags & 0x02) {
        if(!read_dword(pr, &client_key)
        || !read_dword(pr, &server_key)) {
            cbls_close(cbls);
            return;
        }
    }

    if(flags & 0x04) {
        if(!read_dword(pr, &cookie)) {
            cbls_close(cbls);
            return;
        }
    }

    /***/
    cbls_log("[%u] BNLS_HASHDATA", cbls->uid);
    uint32_t hash[5];
    calcHashBuf(data, data_len, (void*)hash);
    if(flags & 0x02) {
        int i;
        uint32_t dbl_hash[7];
        dbl_hash[0] = client_key;
        dbl_hash[1] = server_key;
        for(i = 0; i < 5; i++)
            dbl_hash[i+2] = hash[i];
        calcHashBuf((void*)dbl_hash, 28, (void*)hash);
    }

    /**
     * (DWORD[5]) The data hash.
     *
     * Optional:
     * (DWORD) Cookie. Same as the cookie from the request.
     */
    struct packet_writer pw;
    write_init(&pw, cbls, BNLS_HASHDATA, (flags & 0x04) ? 24 : 20);
    write_raw(&pw, hash, 20);
    if(flags & 0x04)
        write_dword(&pw, cookie);
    write_end(&pw);
}

void
bnls_cdkey_ex(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD)    Cookie. This value has no special meaning to the server and will simply be echoed to the client in the response.
     * (BYTE)     Amount of CD-keys to encrypt. Must be between 1 and 32.
     * (DWORD)    Flags
     * (DWORD[])  Server session key(s) (check flags)
     * (DWORD[])  Client session key(s) (optional; check flags)
     * (STRING[]) CD-keys. No dashes or spaces. The client can use multiple types of CD-keys in the same packet.
     *
     * Flags:
     * CDKEY_SAME_SESSION_KEY (0x01):
     * This flag specifies that all the returned CD-keys will use the same client session key. When used in combination with
     * CDKEY_GIVEN_SESSION_KEY (0x02), a single client session key is specified immediately after the server session key(s).
     * When used without CDKEY_GIVEN_SESSION_KEY (0x02), a client session key isn't sent in the request, and the server will
     * create one. When not used, each CD-key gets its own client session key. This flag has no effect if the amount of CD-keys
     * to encrypt is 1.
     *
     * CDKEY_GIVEN_SESSION_KEY (0x02):
     * This flag specifies that the client session keys to be used are specified in the request. When used in combination with
     * CDKEY_SAME_SESSION_KEY (0x01), a single client session key is specified immediately after the server session key(s). When
     * used without CDKEY_SAME_SESSION_KEY (0x01), an array of client session keys (as many as the amount of CD-keys) is specified.
     * When not used, client session keys aren't included in the request.
     *
     * CDKEY_MULTI_SERVER_SESSION_KEYS (0x04):
     * This flag specifies that each CD-key has its own server session key. When specified, an array of server session keys
     * (as many as the amount of CD-keys) is specified. When not specified, a single server session key is specified. This flag
     * has no effect if the amount of CD-keys to encrypt is 1.
     *
     * CDKEY_OLD_STYLE_RESPONSES (0x08):
     * Specifies that the response to this packet is a number of BNLS_CDKEY (0x01) responses, instead of a BNLS_CDKEY_EX (0x0c)
     * response. The responses are guaranteed to be in the order of the CD-keys' appearance in the request. Note that when this
     * flag is specified, the Cookie cannot be echoed. (It must still be included in the request.)
     */
    int i;
    uint32_t cookie, flags;
    uint8_t num_keys;
    key_hash_t *keys;

    if(!read_dword(pr, &cookie)
    || !read_byte(pr, &num_keys)
    || (num_keys < 1)
    || (num_keys > 32)
    || !read_dword(pr, &flags)) {
        cbls_close(cbls);
        return;
    }

    keys = xmalloc(num_keys * sizeof(key_hash_t));
    memset(keys, 0, num_keys * sizeof(key_hash_t));

    if(flags & 0x04) { // CDKEY_MULTI_SERVER_SESSION_KEYS
        // One server key for each cdkey
        for(i = 0; i < num_keys; i++) {
            if(!read_dword(pr, &keys[i].server_token)) {
                xfree(keys);
                cbls_close(cbls);
                return;
            }
        }
    } else {
        // One server key
        uint32_t server_token;
        if(!read_dword(pr, &server_token)) {
            xfree(keys);
            cbls_close(cbls);
            return;
        }
        for(i = 0; i < num_keys; i++)
            keys[i].server_token = server_token;
    }

    if(flags & 0x02) { // CDKEY_GIVEN_SESSION_KEY
        if(flags & 0x01) { // CDKEY_SAME_SESSION_KEY
            // One client key
            uint32_t client_token;
            if(!read_dword(pr, &client_token)) {
                xfree(keys);
                cbls_close(cbls);
                return;
            }
            for(i = 0; i < num_keys; i++)
                keys[i].client_token = client_token;
        } else {
            // One client key for each cdkey
            if(!read_dword(pr, &keys[i].client_token)) {
                xfree(keys);
                cbls_close(cbls);
                return;
            }
        }
    } else {
        // Generate our own client keys
        for(i = 0; i < num_keys; i++)
            keys[i].client_token = (uint32_t)rand();
    }

    for(i = 0; i < num_keys; i++) {
        if(!(keys[i].cdkey = read_string(pr))) {
            xfree(keys);
            cbls_close(cbls);
            return;
        }
    }

    /***/
    uint32_t num_success = 0;
    uint32_t success_bitmask = 0;
    for(i = 0; i < num_keys; i++) {
        key_hash(&keys[i]);
        if(keys[i].success) {
            num_success++;
            success_bitmask |= (1 << i);
        }
    }

    /**
     * (DWORD) Cookie
     * (BYTE)  Number of CD-keys requested
     * (BYTE)  Number of successfully encrypted CD-keys
     * (DWORD) Bit mask
     *
     * For each successful CD Key:
     * (DWORD)    Client session key
     * (DWORD[9]) CD-key data.
     */
    struct packet_writer pw;
    if(flags & 0x08) {
        for(i = 0; i < num_keys; i++) {
            write_init(&pw, cbls, BNLS_CDKEY, 44);
            write_dword(&pw, keys[i].success);
            write_dword(&pw, keys[i].client_token);
            write_raw(&pw, keys[i].hash, 36);
            write_end(&pw);
        }
    } else {
        write_init(&pw, cbls, BNLS_CDKEY_EX, 10 + (num_success * 40));
        write_dword(&pw, cookie);
        write_dword(&pw, num_keys);
        write_dword(&pw, num_success);
        write_dword(&pw, success_bitmask);
        for(i = 0; i < num_keys; i++) {
            if(!keys[i].success)
                continue;
            write_dword(&pw, keys[i].client_token);
            write_raw(&pw, keys[i].hash, 36);
        }
    }

    /***/
    xfree(keys);
}

void
bnls_choosenlsrevision(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD) NLS Revision Number
     */
    uint32_t nls_rev;
    if(!read_dword(pr, &nls_rev)) {
        cbls_close(cbls);
        return;
    }

    /**/
    cbls_log("[%u] BNLS_CHOOSENLSREVISION %u", cbls->uid, nls_rev);

    /**
     * (BOOLEAN) Success code
     */
    struct packet_writer pw;
    write_init(&pw, cbls, BNLS_CHOOSENLSREVISION, 4);
    if (nls_rev < 0 || nls_rev > 2) {
        //Unsuccessful, unknown NLS Type
        write_dword(&pw, 0);
    } else {
        //Successful
        write_dword(&pw, 1);
        cbls->nls_rev = nls_rev;
    }
    write_end(&pw);
}

void
bnls_authorize(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (STRING) Bot ID
     */
    char *botid;
    if(!(botid = read_string(pr))) {
        cbls_close(cbls);
        return;
    }

    /***/
    cbls_log("[%u] BNLS_AUTHORIZE %s", cbls->uid, botid);

    /**
     * (BOOLEAN) Server code
     */
    struct packet_writer pw;
    write_init(&pw, cbls, BNLS_AUTHORIZE, 4);
    write_dword(&pw, 0);
    write_end(&pw);
}

void
bnls_authorizeproof(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD) Checksum
     */

    /***/
    cbls_log("[%u] BNLS_AUTHORIZEPROOF success", cbls->uid);

    /**
     * (DWORD) Status code (0=Authorized, 1=Unauthorized)
     */
    struct packet_writer pw;
    write_init(&pw, cbls, BNLS_AUTHORIZEPROOF, 4);
    write_dword(&pw, 0);
    write_end(&pw);
}

void
bnls_requestversionbyte(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD) Product ID
     */
    uint32_t prod;
    if(!read_dword(pr, &prod)) {
        prod = 0;
    }

    /***/
    cbls_log("[%u] BNLS_REQUESTVERBYTE %s", cbls->uid, gamestr(prod));
    hash_files_t *hashes = get_hashes(prod);
    if(!hashes)
        prod = 0;

    /**
     * (DWORD) Product ID (0 for error)
     *
     * If product is non-zero:
     * (DWORD) Version byte
     */
    struct packet_writer pw;
    write_init(&pw, cbls, BNLS_REQUESTVERSIONBYTE, 8);
    write_dword(&pw, prod);
    if(prod != 0)
        write_dword(&pw, hashes->ver_byte);
    write_end(&pw);
}

void
bnls_verifyserver(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD)     Server's IP
     * (DWORD[32]) Signature
     */

    /***/
    cbls_log("[%u] BNLS_VERIFYSERVER unimplemented", cbls->uid);
    uint32_t success = 0;

    /**
     * (BOOLEAN) Success
     */
    struct packet_writer pw;
    write_init(&pw, cbls, BNLS_VERIFYSERVER, 4);
    write_dword(&pw, success);
    write_end(&pw);
}

void
bnls_reserveserverslots(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD) Number of slots to reserve
     * BNLS may limit the number of slots to a reasonable value
     */

    /***/
    cbls_log("[%u] BNLS_RESERVESERVERSLOTS unimplemented", cbls->uid);
    uint32_t slots = 0;

    /**
     * (DWORD) Number of slots reserved
     */
    struct packet_writer pw;
    write_init(&pw, cbls, BNLS_RESERVESERVERSLOTS, 4);
    write_dword(&pw, slots);
    write_end(&pw);
}

void
bnls_serverlogonchallenge(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD)     Slot Index
     * (DWORD)     NLS Revision Number
     * (DWORD[16]) Data from Account Database
     * (DWORD[8])  Data from SID_AUTH_ACCOUNTLOGON
     */

    /***/
    cbls_log("[%u] BNLS_SERVERLOGONCHALLENGE unimplemented", cbls->uid);
    cbls_close(cbls);
    return;

    /**
     * (DWORD)     Slot index
     * (DWORD[16]) Data for SID_AUTH_ACCOUNTLOGON
     */
}

void
bnls_serverlogonproof(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD)    Slot Index
     * (DWORD[5]) Data from SID_AUTH_ACCOUNTLOGONPROOF
     * (STRING)   The client's Account Name
     */

    /***/
    cbls_log("[%u] BNLS_SERVERLOGONPROOF unimplemented", cbls->uid);
    cbls_close(cbls);
    return;

    /**
     * (DWORD)    Slot index.
     * (BOOLEAN)  Success
     * (DWORD[5]) Data for SID_AUTH_ACCOUNTLOGONPROOF
     */
}

void
bnls_versioncheckex(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD)  Product ID
     * (DWORD)  Version DLL digit in the range 0-7 (For example, for IX86Ver1.mpq, the digit is 1)
     * (DWORD)  Flags (must be set to 0 or you will be disconnected!)
     * (DWORD)  Cookie
     * (STRING) Checksum Formula
     */
    uint32_t productid;
    uint32_t version_dll;
    uint32_t flags;
    uint32_t cookie;
    char *checksum_formula;

    if (!read_dword(pr, &productid)
    || !read_dword(pr, &version_dll)
    || !read_dword(pr, &flags)
    || !read_dword(pr, &cookie)
    || !(checksum_formula = read_string(pr))) {
        cbls_close(cbls);
        return;
    }

    /***/
    cbls_log("[%u] BNLS_VERSIONCHECKEX unimplemented", cbls->uid);
    cbls_close(cbls);
    return;

    /**
     * (BOOLEAN) Success
     *
     * If success is true:
     * (DWORD)  Version
     * (DWORD)  Checksum
     * (STRING) Version check stat string
     * (DWORD)  Cookie
     * (DWORD)  The latest version code for this product
     *
     * Otherwise:
     * (DWORD) Cookie
     */
    struct packet_writer pw;
    write_init(&pw, cbls, BNLS_VERSIONCHECKEX2, 8);
    write_dword(&pw, 0);
    write_dword(&pw, cookie);
    write_end(&pw);}

void
bnls_versioncheckex2(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (DWORD)  Product ID
     * (DWORD)  Flags (must be set to 0 or you will be disconnected!)
     * (DWORD)  Cookie
     * (QWORD)  Timestamp for Version Check Archive
     * (STRING) Version Check Archive Filename
     * (STRING) Checksum Formula
     */
    uint32_t product_id;
    uint32_t flags;
    uint32_t cookie;
    uint64_t timestamp;
    char *vc_filename;
    char *checksum_formula;

    if(!read_dword(pr, &product_id)
    || !read_dword(pr, &flags)
    || !read_dword(pr, &cookie)
    || !read_qword(pr, &timestamp)
    || !(vc_filename = read_string(pr))
    || !(checksum_formula = read_string(pr))) {
        cbls_close(cbls);
        return;
    }

    if(flags) {
        packet_log("BNLS_VERSIONCHECKEX2 flags != 0", pr->ih);
        cbls_close(cbls);
        return;
    }

    /***/
    cbls_log("[%u] BNLS_VERSIONCHECKEX2 %s %s", cbls->uid, gamestr(product_id), vc_filename);
    uint32_t success, version, checksum;
    char statstr[128];
    memset(statstr, 0, 128);
    success = 0;

    hash_files_t *hashes = get_hashes(product_id);

    if(hashes && hashes->f_game) {
        /* if(hashes->f_img) */
        if((product_id == PRODUCT_STAR)
        || (product_id == PRODUCT_SEXP)
        || (product_id == PRODUCT_W2BN)) {
            char lockdownfile[64];
            strcpy(lockdownfile, "IX86/");
            strcat(lockdownfile, vc_filename);
            strcpy(lockdownfile+strlen(lockdownfile)-4, ".dll");

            success = ldCheckRevision(hashes->f_game, hashes->f_storm, hashes->f_snp, checksum_formula,
                    &version, &checksum, statstr,
                    lockdownfile, hashes->f_img);
            if(!success)
                cbls_log("[%u] ldCheckRevision() failed!", cbls->uid);
            else
                success = strlen(statstr);
        } else {
            int mpqNumber = extractMPQNumber(vc_filename);
            if(mpqNumber >= 0) {
                success = checkRevisionFlat(
                        checksum_formula, hashes->f_game, hashes->f_storm, hashes->f_snp, mpqNumber, &checksum);
                if(success) {
                    success = getExeInfo(
                            hashes->f_game, statstr, 128, &version, BNCSUTIL_PLATFORM_X86);
                    if(!success)
                        cbls_log("[%u] getExeInfo() failed", cbls->uid);
                } else {
                    cbls_log("[%u] checkRevision() failed", cbls->uid);
                }
            } else {
                cbls_log("[%u] failed to extract mpq number from %s", cbls->uid, vc_filename);
            }
        }
    } else {
        cbls_log("[%u] unknown product %u", cbls->uid, product_id);
    }

    /**
     * (BOOLEAN) Success
     *
     * If success is true:
     * (DWORD)  Version
     * (DWORD)  Checksum
     * (STRING) Version check stat string
     * (DWORD)  Cookie
     * (DWORD)  The latest version code for this product
     *
     * Otherwise:
     * (DWORD) Cookie
     */
    struct packet_writer pw;
    // success contains strlen(statstr)
    write_init(&pw, cbls, BNLS_VERSIONCHECKEX2, (success == 0) ? 8 : 21 + success);
    write_dword(&pw, !!success);
    if(!success) {
        write_dword(&pw, cookie);
    } else {
        write_dword(&pw, version);
        write_dword(&pw, checksum);
        write_string(&pw, statstr);
        write_dword(&pw, cookie);
        write_dword(&pw, hashes->ver_byte);
    }
    write_end(&pw);
}

void
bnls_warden(struct packet_reader *pr) {
    struct cbls_conn *cbls = pr->cbls;
    /**
     * (BYTE)  Command
     * (DWORD) Cookie
     */
    uint8_t command;
    uint32_t cookie;
    if(!read_byte(pr, &command)
    || !read_dword(pr, &cookie)) {
        snd_warden_error(pr->cbls, 0, cookie, WARDEN_RESULT_REQUEST_CORRUPT);
        return;
    }

    /***/
    switch(command) {
    case 0:
        bnls_warden_0(pr, cookie);
        return;
    case 1:
        bnls_warden_1(pr, cookie);
        return;
    case 2:
        bnls_warden_2(pr, cookie);
        return;
    case 3:
        bnls_warden_3(pr, cookie);
        return;
    default:
        cbls_log("[%u] BNLS_WARDEN unknown command %u", command);
        break;
    }

    /**
     * (BYTE)  Command
     * (DWORD) Cookie
     * (BYTE)  Result
     * (WORD)  Lengh of data
     * (VOID)  Data
     */
    snd_warden_error(cbls, command, cookie, WARDEN_RESULT_REQUEST_CORRUPT);
}
