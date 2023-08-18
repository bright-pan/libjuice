#if defined(AOS_COMP_CLI)
#include <aos/cli.h>
#include <aos/kernel.h>
#include <stdio.h>   /* printf */
#include <stdlib.h>  /* atoi, malloc */
#include <string.h>  /* strcpy */
#include "log.h"
#include "uthash.h"

struct my_struct {
    int id;                    /* key */
    char name[21];
    UT_hash_handle hh;         /* makes this structure hashable */
};

struct my_struct *users = NULL;

void add_user(int user_id, const char *name)
{
    struct my_struct *s;

    HASH_FIND_INT(users, &user_id, s);  /* id already in the hash? */
    if (s == NULL) {
        s = (struct my_struct*)malloc(sizeof *s);
        s->id = user_id;
        HASH_ADD_INT(users, id, s);  /* id is the key field */
    }
    strcpy(s->name, name);
}

struct my_struct *find_user(int user_id)
{
    struct my_struct *s;

    HASH_FIND_INT(users, &user_id, s);  /* s: output pointer */
    return s;
}

void delete_user(struct my_struct *user)
{
    HASH_DEL(users, user);  /* user: pointer to deletee */
    free(user);
}

void delete_all()
{
    struct my_struct *current_user;
    struct my_struct *tmp;

    HASH_ITER(hh, users, current_user, tmp) {
        HASH_DEL(users, current_user);  /* delete it (users advances to next) */
        free(current_user);             /* free it */
    }
}

void print_users()
{
    struct my_struct *s;

    for (s = users; s != NULL; s = (struct my_struct*)(s->hh.next)) {
        printf("user id %d: name %s\n", s->id, s->name);
    }
}

int by_name(const struct my_struct *a, const struct my_struct *b)
{
    return strcmp(a->name, b->name);
}

int by_id(const struct my_struct *a, const struct my_struct *b)
{
    return (a->id - b->id);
}

int test_uthash(int argc, char **argv)
{
    static int id = 1;
    struct my_struct *s;
    int temp;
    if (argc < 2) {
        printf("%s 1 name [add user]\n", argv[0]);
        printf("%s 2 id name [add or rename user by id]\n", argv[0]);
        printf("%s 3 id [find user]\n", argv[0]);
        printf("%s 4 id [delete user]\n", argv[0]);
        printf("%s 5 [delete all users]\n", argv[0]);
        printf("%s 6 [sort items by name]\n", argv[0]);
        printf("%s 7 [sort items by id]\n", argv[0]);
        printf("%s 8 [print users]\n", argv[0]);
        printf("%s 9 [count users]\n", argv[0]);
    } else {
        switch (atoi(argv[1])) {
            case 1:
                add_user(id++, argv[2]);
                break;
            case 2:
                temp = atoi(argv[2]);
                add_user(temp, argv[3]);
                break;
            case 3:
                s = find_user(atoi(argv[2]));
                printf("user: %s\n", s ? s->name : "unknown");
                break;
            case 4:
                s = find_user(atoi(argv[2]));
                if (s) {
                    delete_user(s);
                } else {
                    printf("id unknown\n");
                }
                break;
            case 5:
                delete_all();
                break;
            case 6:
                HASH_SORT(users, by_name);
                break;
            case 7:
                HASH_SORT(users, by_id);
                break;
            case 8:
                print_users();
                break;
            case 9:
                temp = HASH_COUNT(users);
                printf("there are %d users\n", temp);
                break;
        }
    }
    return 0;
}


ALIOS_CLI_CMD_REGISTER(test_uthash, test_uthash, test_uthash);
#endif