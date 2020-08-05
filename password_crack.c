/**
 * Password cracking program
 * Christopher Holzweber, 11803108
 * System oriented programming, WS 2018/2019
 */

/* You can use the GNU extensions */
#define _GNU_SOURCE
#include <time.h> /*for time calculation as given in the task*/
#include <errno.h> /*for setting errno = 0 as given in the task*/
/*Any additional headers you might need*/
#include <stdlib.h>
#include <stdio.h>
/* Speical import: Hashing functions */
#include <openssl/sha.h>

/* Return values of the program */
#define SUCCESS				0
#define INVALID_PARAM_COUNT		1
#define INVALID_PARAM			2
#define PASSWORD_FILE_NOT_FOUND		3
#define PASSWORD_FILE_READ_ERROR	4
#define MEMORY_ERROR			5
#define INVALID_FILE_FORMAT		6

/* Limits on the minimum and maximum values of the lower/upper bound of password length.
Obvioulsy the upper bound must be equal or larger than the lower bound as well! */
#define MINIMUM_LOWER	1 /* Lower bound must be between 1 and 4 */
#define MINIMUM_UPPER	4
#define MAXIMUM_LOWER	1 /* Upper bound must be between 1 and 5 */
#define MAXIMUM_UPPER	5

/* Helper function to automatically calculate the maximum of two values */
#define MAX(a,b) (((a)>(b))?(a):(b))

/* Internal encoding of the hash algorithms we support */
#define HASH_ALG_SHA1	1
#define HASH_ALG_SHA256	2
/* Maximum length for the hash value. This allows us to create a buffer on the stack and avoid having to malloc it.
Note: In "modern" C you could easily create an array of dynamic (=runtime-calculated) length on the stack.
But ANSI-C requires arrays to have a static (compile-time) length! */
#define MAX_HASH_LEN MAX(SHA_DIGEST_LENGTH,SHA256_DIGEST_LENGTH)

/* After how many passwords we print the current state */
#define DUMP_COUNT 1000

/* Length of your salt in bytes */
#define SALT_LEN 10

/* return values for functions/methods*/
#define TRUE 1
#define FALSE 0
/* A new datatype for our salt */
typedef unsigned char Salt[SALT_LEN];

/* How to store the passwords in memory: Username and password are strings (zero-terminated), hash and salt are arrays of
"fixed" (salt: SALT_LEN, hash: depends on algorithm) length and NOT zero-terminated! algorithm is the internal representation
(see above) of the algorithm used */
typedef struct
{
    char *username;	/* Username; zero-terminated. Used only for displaying */
    unsigned char *hash;	/* NOT \0-terminated (already binary)! Length depends on algorithm */
    char *password;	/* Cracked passsword or NULL if not yet discovered */
    int algorithm;	/* Internal numbering; see constants above */
    Salt salt;	/* NOT \0-terminated! */
} PasswordEntry;

/* The character set we use for generating passwords. Note that this is not "define" but a global variable. */
static const char passwordCharacterSet[]="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/* Prototypes for the functions below. Documentation is at the implementation. */
int compareTo(char * destination, char * source);
int stringlen(char * source);
unsigned char charToByte(char * source, int index);
int getLines(FILE * fpointer);
void lastCharToStringEnder(char * string, char ender);
void printDataStructure(PasswordEntry * passwordData, int size);
void freeAllocMemBackwards(PasswordEntry * passwordData, int index);
void sort(PasswordEntry * passwordData, int size);
int cmpSalts(Salt salt1, Salt salt2);
int breakPasswords(PasswordEntry * passwordData, int minLen, int maxLen, int maxNrOfPasswords);
int compareHash(unsigned char * hash1, unsigned char * hash2, int algotype);

int main(int argc, char * argv[]) {
  /*variables for creating mode*/
  int numberOfElements = 0; /*stores the number of elements in the data-array used in creating mode*/
  unsigned char * data = NULL; /*pointer which will point to dataarray iff in creating mode*/
  unsigned char * pData = NULL; /* helper- pointer which will point to dataarray iff in creating mode*/
  unsigned char * pSalt = NULL; /* helper- pointer which will point to saltarray iff in creating mode*/
  char * pPassw = NULL; /* helper- pointer which will point to password iff in creating mode*/

  /*variables for breaking mode*/
  int timecheck = 0; /*checks if optional parameter is set*/
  time_t secondsStart;
  time_t secondsEnd;
  time_t duration;
  char * filename = NULL; /*stores entered filename*/
  FILE * fpointer = NULL; /*points to actual file*/
  int nrOfPassw = 0; /*stores number of password lines*/
  char * cp = NULL; /*char pointer used for file handling*/
  char * sAlgotype = NULL; /*helper strings*/
  char * sSalt = NULL;
  char * sSH1 = NULL;
  char * sSH256 = NULL;
  size_t len = 0;
  int minLen = 0; /*min leng of password cracking*/
  int maxLen = 0; /*max leng of password cracking*/
  PasswordEntry * passwordData = NULL; /*stores passwordfile data in struct*/

  /*variables used for loops*/
  int count = 0;
  int j = 0;
  int i = 0;
  /*fullfill task*/
  errno = 0;
  /*First we need to check if 4 to 5 parametes were given(the first one is always the filename)*/
  if (argc < 5 || argc > 6) {
    return INVALID_PARAM_COUNT;
  }

  if (compareTo("-c", argv[1])) /*creating mode*/ {

    PasswordEntry pe; /*store passwort information in struct*/

    if (stringlen(argv[2]) >= MINIMUM_LOWER) /*checks if it is at least 1 byte long*/ {
      pe.username = argv[2]; /*username chararray now points to the argument username(zero term.), not copied!*/
    } else {
      return INVALID_PARAM; /*not a correct username used*/
    }

    if (stringlen(argv[3]) >= MINIMUM_LOWER && stringlen(argv[3]) <= MAXIMUM_UPPER) /*checks if it is at least 1 byte long*/ {
      pe.password = argv[3]; /*password chararray now points to the argument password(zero term.), not copied!*/
    } else {
      return INVALID_PARAM; /*not a correct password used*/
    }

    if (compareTo("SHA1", argv[4])) /*now checks if algo 1 oder 2 is used.*/ {
      pe.algorithm = HASH_ALG_SHA1;
    } else if (compareTo("SHA2", argv[4])) {
      pe.algorithm = HASH_ALG_SHA256;
    } else {
      return INVALID_PARAM; /*not a correct algo used*/
    }

    if (argc == 6) /*check if optional fith parameter even exists.*/ {
      if (stringlen(argv[5]) > SALT_LEN * 2 || stringlen(argv[5]) % 2 != 0) /*salt is not allowed to be bigger then 20 chars or it is an odd number*/ {
        return INVALID_PARAM; /*not a correct algo used*/
      } else {
        int i = 0;
        int j = 0;
        while (j < stringlen(argv[5])) {
          pe.salt[i++] = charToByte(argv[5], j); /*takes two chars and convert to byte value*/
          j = j + 2; /*go 2 indexes to the right, always possiblem because we have modulo 2 check*/
        }
        while (i < SALT_LEN) /*fill up with zeros to the right*/ {
          pe.salt[i++] = 0x00;
        }
      }

    } else {
      /*transform string into fitting salt array with only 0 bytes.*/
      int i = 0;
      while (i < SALT_LEN) {
        pe.salt[i++] = 0x00;
      }
    }
    /*creating the pointer, for later hasing in form of salt|passw without the ending 0 of the password string.*/
    /*for this purpose we need to reserve some memory, because we dont know the exact size erlier.*/
    numberOfElements = SALT_LEN + 1 + stringlen(pe.password); /*1 because salt has 10 bytes and the slash | has 1 byte fixed everytime*/
    data = (unsigned char * ) malloc(numberOfElements * sizeof(unsigned char)); /*allocates memory for the data to be hashed*/
    if (data == NULL) /* Memory allocation fails */ {
      return MEMORY_ERROR;
    }

    /*build the data which will be hashed*/
    pData = data;
    pSalt = pe.salt;
    pPassw = pe.password;

    for (count = 0; count < SALT_LEN; count++) /*salt always has size 10*/ {
      * pData++ = * pSalt++;
    }
    * pData++ = '|';
    while ( * pPassw != '\0') {
      * pData++ = * pPassw++;
    }

    /*hash the created data-array and print the result to the output.*/
    if (pe.algorithm == HASH_ALG_SHA1) {
      pe.hash = SHA1(data, numberOfElements, pe.hash); /*get hash sha1*/
      printf("SHA1;");
      count = 0;
      while (count < SALT_LEN) {
        printf("%02X", pe.salt[count++]);
      }
      printf(";");

      count = 0;
      while (count < SHA_DIGEST_LENGTH) {
        printf("%02X", pe.hash[count++]);
      }
      printf(";");

    } else {
      pe.hash = SHA256(data, numberOfElements, pe.hash); /*get hash sha256*/
      printf("SHA2;");
      count = 0;
      while (count < SALT_LEN) {
        printf("%02X", pe.salt[count++]);
      }
      printf(";");

      count = 0;
      while (count < SHA256_DIGEST_LENGTH) {
        printf("%02X", pe.hash[count++]);
      }
      printf(";");

    }
    printf("%s\n", pe.username);

    /*free allocated memory of data-array*/
    free(data);
  } else if (compareTo("-b", argv[1])) /*breaking mode*/ {

    if (argc == 6) /*check if the optional value is there*/ {
      if (compareTo("-t", argv[2])) {
        timecheck = 1; /*we have to work with time checking*/
      } else {
        return INVALID_PARAM; /*wrong parameter!*/
      }
    } else {
      timecheck = 0; /*we do not have to work with time checking*/
    }

    filename = argv[2 + timecheck]; /*get filename*/

    /*get min passw leng to be tested*/
    if (stringlen(argv[3 + timecheck]) != 1) /*checks if there is only 1 digit given*/ {
      return INVALID_PARAM;
    }
    cp = argv[3 + timecheck];
    minLen = (int)( * cp - '0'); /*convert char to integer for later check*/
    if (minLen < MINIMUM_LOWER || minLen > MINIMUM_UPPER) {
      return INVALID_PARAM;
    }

    /*get max passw leng to be tested*/
    if (stringlen(argv[4 + timecheck]) != 1) /*checks if there is only 1 digit given*/ {
      return INVALID_PARAM;
    }
    cp = argv[4 + timecheck];
    maxLen = (int)( * cp - '0'); /*convert char to integer for later check*/
    if (maxLen < MAXIMUM_LOWER || maxLen > MAXIMUM_UPPER || maxLen < minLen) {
      return INVALID_PARAM;
    }

    /*open file for reading*/
    fpointer = fopen(filename, "r");
    if (fpointer == NULL) /*check if file is readable*/ {
      return PASSWORD_FILE_NOT_FOUND;
    }
    /*check how many lines are in the file, in forder to reserver exact memory*/
    nrOfPassw = getLines(fpointer);
    if (nrOfPassw <= 0) /*checks if there was an read error during counting the lines*/ {
      fclose(fpointer); /*close file*/
      return PASSWORD_FILE_READ_ERROR;
    }

    /*allocate memory for passwort structures*/
    passwordData = (PasswordEntry * ) malloc(nrOfPassw * sizeof(PasswordEntry)); /*allocates memory for the passw data to be stored*/
    if (passwordData == NULL) /* Memory allocation fails */ {
      fclose(fpointer); /*close file*/
      return MEMORY_ERROR;
    }

    /*fill allocated memory*/
    rewind(fpointer); /*set pointer back to beginnung of the file*/

    /*set all fields needed for later autoalloc to null*/
    for (count = 0; count < nrOfPassw; count++) {
      passwordData[count].username = NULL;
      passwordData[count].password = NULL;
    }
    /*fill allocated memory*/
    for (count = 0; count < nrOfPassw; count++) {
      sAlgotype = NULL; /*helper strings*/
      sSalt = NULL;
      sSH1 = NULL;
      sSH256 = NULL;
      len = 0;

      /*get algorithm type out of file(first field)*/
      if (getdelim( & sAlgotype, & len, ';', fpointer) < 0) {
        /*if there was an error while reading,
        we close everything and return an error*/
        freeAllocMemBackwards(passwordData, count);
        /*Free helpers*/
        free(sAlgotype);
        free(sSalt);
        /*close file*/
        fclose(fpointer);
        /*free allocated mem.*/
        free(passwordData);
        return PASSWORD_FILE_READ_ERROR;
      }
      lastCharToStringEnder(sAlgotype, ';'); /*trim away semicolon*/

      /*set the correct integer value for the algorithm used*/
      if (compareTo("SHA1", sAlgotype)) {
        passwordData[count].algorithm = HASH_ALG_SHA1;
      } else if (compareTo("SHA2", sAlgotype)) {
        passwordData[count].algorithm = HASH_ALG_SHA256;
      }

      /*get salt from password file*/
      if (getdelim( & sSalt, & len, ';', fpointer) < 0) {
        /*if there was an error while reading,
        we close everything and return an error*/
        freeAllocMemBackwards(passwordData, count);
        /*Free helpers*/
        free(sAlgotype);
        free(sSalt);
        /*close file*/
        fclose(fpointer);
        /*free allocated mem.*/
        free(passwordData);
        return PASSWORD_FILE_READ_ERROR;
      }
      lastCharToStringEnder(sSalt, ';'); /*trim away semicolon*/

      /*check if Salt is of SALT_LEN, otherwise file is incorrect!*/
      if (stringlen(sSalt) != SALT_LEN * 2) {

        /*file error*/
        freeAllocMemBackwards(passwordData, count);
        /*Free helpers*/
        free(sAlgotype);
        free(sSalt);
        /*close file*/
        fclose(fpointer);
        /*free allocated mem.*/
        free(passwordData);
        return INVALID_FILE_FORMAT;
      }

      j = 0;
      i = 0;
      while (j < SALT_LEN * 2) {
        passwordData[count].salt[i++] = charToByte(sSalt, j); /*takes two chars and convert to byte value*/
        j = j + 2; /*go 2 indexes to the right, always possiblem because we have modulo 2 check*/
      }

      if (compareTo(sAlgotype, "SHA1")) {

        if (getdelim( & sSH1, & len, ';', fpointer) < 0) {
          /*if there was an error while reading,
          we close everything and return an error*/
          freeAllocMemBackwards(passwordData, count);
          /*Free helpers*/
          free(sAlgotype);
          free(sSalt);
          free(sSH1);
          /*close file*/
          fclose(fpointer);
          /*free allocated mem.*/
          free(passwordData);
          return PASSWORD_FILE_READ_ERROR;
        }
        lastCharToStringEnder(sSH1, ';');
        /*check if SHA1 is of length SHA, otherwise file is incorrect!*/
        if (stringlen(sSH1) != SHA_DIGEST_LENGTH * 2) {
          /*file error*/
          freeAllocMemBackwards(passwordData, count);
          /*Free helpers*/
          free(sAlgotype);
          free(sSalt);
          free(sSH1);
          /*close file*/
          fclose(fpointer);
          /*free allocated mem.*/
          free(passwordData);
          return INVALID_FILE_FORMAT;
        }

        /*allocates memory for the hash data to be stored*/
        passwordData[count].hash = (unsigned char * ) malloc(SHA_DIGEST_LENGTH * sizeof(unsigned char));
        if (passwordData[count].hash == NULL) {
          /*if there was an error while reading,
          we close everything and return an error*/
          freeAllocMemBackwards(passwordData, count);
          /*Free helpers*/
          free(sAlgotype);
          free(sSalt);
          free(sSH1);
          /*close file*/
          fclose(fpointer);
          /*free allocated mem.*/
          free(passwordData);
          return MEMORY_ERROR;
        }
        /*set to byte values*/
        j = 0;
        for (i = 0; i < SHA_DIGEST_LENGTH * 2; i = i + 2) {
          passwordData[count].hash[j++] = charToByte(sSH1, i);
        }

        if (getdelim( & passwordData[count].username, & len, '\n', fpointer) < 0) {
          /*if there was an error while reading,
          we close everything and return an error*/
          freeAllocMemBackwards(passwordData, count);
          /*Free helpers*/
          free(sAlgotype);
          free(sSalt);
          free(sSH1);
          /*close file*/
          fclose(fpointer);
          /*free allocated mem.*/
          free(passwordData);
          return PASSWORD_FILE_READ_ERROR;
        }
        lastCharToStringEnder(passwordData[count].username, '\n');

        free(sSH1);
      } else if (compareTo(sAlgotype, "SHA2")) {

        if (getdelim( & sSH256, & len, ';', fpointer) < 0) {
          /*if there was an error while reading,
          we close everything and return an error*/
          freeAllocMemBackwards(passwordData, count);
          /*Free helpers*/
          free(sAlgotype);
          free(sSalt);
          free(sSH256);
          /*close file*/
          fclose(fpointer);
          /*free allocated mem.*/
          free(passwordData);
          return PASSWORD_FILE_READ_ERROR;
        }
        lastCharToStringEnder(sSH256, ';');
        /*check if SHA256 is of length SHA256, otherwise file is incorrect!*/
        if (stringlen(sSH256) != SHA256_DIGEST_LENGTH * 2) {

          /*file error*/
          freeAllocMemBackwards(passwordData, count);
          /*Free helpers*/
          free(sAlgotype);
          free(sSalt);
          free(sSH256);
          /*close file*/
          fclose(fpointer);
          /*free allocated mem.*/
          free(passwordData);
          return INVALID_FILE_FORMAT;
        }

        /*allocates memory for the hash data to be stored*/
        passwordData[count].hash = (unsigned char * ) malloc(SHA256_DIGEST_LENGTH * sizeof(unsigned char));
        if (passwordData[count].hash == NULL) {
          /*if there was an error while reading,
          we close everything and return an error*/
          freeAllocMemBackwards(passwordData, count);
          /*Free helpers*/
          free(sAlgotype);
          free(sSalt);
          free(sSH256);
          /*close file*/
          fclose(fpointer);
          /*free allocated mem.*/
          free(passwordData);
          return MEMORY_ERROR;
        }
        /*set to byte values*/
        j = 0;
        for (i = 0; i < SHA256_DIGEST_LENGTH * 2; i = i + 2) {
          passwordData[count].hash[j++] = charToByte(sSH256, i);
        }

        if (getdelim( & passwordData[count].username, & len, '\n', fpointer) < 0) {
          /*if there was an error while reading,
          we close everything and return an error*/
          freeAllocMemBackwards(passwordData, count);
          /*Free helpers*/
          free(sAlgotype);
          free(sSalt);
          free(sSH256);
          /*close file*/
          fclose(fpointer);
          /*free allocated mem.*/
          free(passwordData);
          return PASSWORD_FILE_READ_ERROR;
        }
        lastCharToStringEnder(passwordData[count].username, '\n');

        free(sSH256);
      } else /*NOT a valid coding was used*/ {
        /*file error*/
        /*Free helpers*/
        free(sAlgotype);
        free(sSalt);
        freeAllocMemBackwards(passwordData, count);
        /*close file*/
        fclose(fpointer);
        /*free allocated mem.*/
        free(passwordData);
        return INVALID_FILE_FORMAT;
      }

      /*Free helpers*/
      free(sAlgotype);
      free(sSalt);
    }

    /*sort datastrcuture*/
    sort(passwordData, nrOfPassw);
    printf("Hashes to crack:\n");
    printDataStructure(passwordData, nrOfPassw);
    printf("\n");
    time( & secondsStart);
    /*TODO BREAKING*/
    if (!breakPasswords(passwordData, minLen, maxLen, nrOfPassw)) /*checks if there was no memory alloc error*/ {
      freeAllocMemBackwards(passwordData, nrOfPassw - 1);
      /*close file*/
      fclose(fpointer);
      /*free allocated mem.*/
      free(passwordData);
      return MEMORY_ERROR;
    }
    /*breaking worked out fine*/
    if (timecheck) {
      time( & secondsEnd);
      duration = secondsEnd - secondsStart;
      printf("\nTime elapsed: %ld second(s)\n", duration);
    }
    printf("\nEnd result:\n");
    printDataStructure(passwordData, nrOfPassw);

    /*free all allocated lcoks within the structures*/
    freeAllocMemBackwards(passwordData, nrOfPassw - 1);
    /*close file*/
    fclose(fpointer);
    /*free allocated mem.*/
    free(passwordData);
  } else {
    return INVALID_PARAM; /*no mode selected*/
  }
  return SUCCESS;
}

/**
 * This method checks if two strings are identical
 * return  0 (false) iff strings are not equal
 **/
int compareTo(char * destination, char * source) {
  while ( * source != '\0') {
    if ( * destination == '\0' || * destination++ != * source++) {
      return FALSE;
    }
  }
  /*end of source is reached, check if also the end of destination is reached*/
  if ( * destination != * source) {
    return FALSE;
  }

  return TRUE;
}
/**
 * counts length of string until \ 0 is reached
 * so in order to use this method u have to be sure you are
 * using a 0 terminated string!
 */
int stringlen(char * source) {
  int i = 0;
  while ( * source++ != '\0') {
    i++;
  }
  return i;
}

/**
 * converts 2 chars into 1 byte, gives it back as unsigned char(1byte)
 */
unsigned char charToByte(char * source, int index) {
  unsigned char returnvalue = 0x00; /*set the byte to zero*/
  unsigned char c1;
  unsigned char c2;
  if (source[index] >= 'a' && source[index] <= 'f') {
    c1 = (unsigned char)(source[index++] - 'a') + 10; /*adding ten because letters start at 10*/
  } else if (source[index] >= 'A' && source[index] <= 'F') {
    c1 = (unsigned char)(source[index++] - 'A') + 10; /*adding ten because letters start at 10*/
  } else {
    c1 = (unsigned char) source[index++] - '0'; /*simple ascii arithme.*/
  }

  if (source[index] >= 'a' && source[index] <= 'f') {
    c2 = (unsigned char)(source[index] - 'a') + 10; /*adding ten because letters start at 10*/
  } else if (source[index] >= 'A' && source[index] <= 'F') {
    c2 = (unsigned char) source[index] - 'A' + 10;
  } else {
    c2 = (unsigned char) source[index] - '0';
  }

  /*now shifting the upper 4 bits to bytes 4-8 and then bitwise or the lower 4 bytes to it*/
  returnvalue = c1 << 4;
  returnvalue = returnvalue | c2;
  return returnvalue;
}

/**
 * This method is used to tell the user the amount of lines in a file
 *return a negativ number, if there was an reading error
 */
int getLines(FILE * fpointer) {

  int i = 0;
  char c;
  int loopflag = TRUE;
  while (loopflag) /*means while true*/ {
    c = fgetc(fpointer);

    if (c == EOF) {
      loopflag = FALSE; /*stops loop*/
    } else if (c == '\n') {
      i++;
    }
  }
  if (ferror(fpointer) != 0) /*check if there was an read error*/ {
    return -1;
  } else {
    return i;
  }
}
/**
 * In order to use the automatic allocation correctly, sometimes it is needed
 *to trim away the last char of a actual string at set it to an string ender
 */
void lastCharToStringEnder(char * string, char ender) {
  char * p = string;
  while ( * p != ender) {
    p++;
  }
  * p = '\0';
}
/**
 *prints data structures to the output
 */
void printDataStructure(PasswordEntry * passwordData, int size) {

  int count = 0;
  int j = 0;

  for (count = 0; count < size; count++) {

    /*prints username*/
    printf("%s: ", passwordData[count].username);
    /*prints hash*/
    j = 0;
    if (passwordData[count].algorithm == HASH_ALG_SHA1) {
      while (j < SHA_DIGEST_LENGTH) {
        printf("%02X", passwordData[count].hash[j++]);
      }
    } else {
      while (j < SHA256_DIGEST_LENGTH) {
        printf("%02X", passwordData[count].hash[j++]);
      }
    }

    printf(" = ");
    /*prints password*/
    if (passwordData[count].password == NULL) /*checks if password exists*/ {
      printf("??? ");
    } else {
      printf("%s ", passwordData[count].password);
    }
    /*prints algorithm*/
    if (passwordData[count].algorithm == HASH_ALG_SHA1) {
      printf("(SHA1/");
    } else {
      printf("(SHA2/");
    }
    /*prints salt*/
    j = 0;
    while (j < SALT_LEN) {
      printf("%02X", passwordData[count].salt[j++]);
    }
    printf(")\n");
  }

}
/**
 * Starting from the last structure elements, frees all located memory
 * within a structure, before freeing the structure itself
 */
void freeAllocMemBackwards(PasswordEntry * passwordData, int index) {
  for (; index >= 0; index--) {
    free(passwordData[index].hash);
    free(passwordData[index].password);
    free(passwordData[index].username);
  }
}
/**
 * breaks passwords from given datastructure within given range.
 * the funciton is split in 5 parts, where each part is doing exactly the same
 *just the indexes of the helper arrays are different and also the loops are
 * modified, so we can test all possible passwords from 1 up to 5 digits.
 *the detailed explanation therefore is only in the first part, because all
 *the others work as mentioned exactly the same way.
 *
 * return true if everything worked out fine
 * return false if there was an allocation error
 */
int breakPasswords(PasswordEntry * passwordData, int minLen, int maxLen, int maxNrOfPasswords) {
  unsigned long int tried = 0; /*nr of tried passwords*/
  int cracked = 0; /*nr of cracked passwords*/
  const char * p1 = NULL; /*the pointers p1-p5 are used to point at the string passwordCharacterSet */
  const char * p2 = NULL;
  const char * p3 = NULL;
  const char * p4 = NULL;
  const char * p5 = NULL;
  char * password = NULL;
  int passwordMember = 0; /*password line to be cracked soon*/
  int passwordMemberReset = 0; /*helper variable*/
  int i = 0; /*loop counter for salt transmission*/
  int memberJump = 0; /*if all members are tested, we can jump to the next salt/algo group*/
  unsigned char calcHash1[SHA_DIGEST_LENGTH]; /*reserve memory for hash value, so we dont have to malloc everytime*/
  unsigned char * cH1 = calcHash1;
  unsigned char calcHash2[SHA256_DIGEST_LENGTH];
  unsigned char * cH2 = calcHash2;
  unsigned char singleHash[12]; /*salt + dilimeter + one char*/
  unsigned char twoHash[13]; /*salt + dilimeter + two char*/
  unsigned char threeHash[14]; /*salt + dilimeter + three char*/
  unsigned char fourHash[15]; /*salt + dilimeter + four char*/
  unsigned char fiveHash[16]; /*salt + dilimeter + five char*/
  int hashArraySize = 12; /*for better readability, gets size of array singleHash,twoHash,.. for later use*/
  int flag = 0; /*works like an boolean here*/
  /*hash passwords with one digit*/
  if (minLen == 1 && maxLen >= 1) /*here only single digit passwords are tested*/ {

    p1 = passwordCharacterSet;
    while ( * p1 != '\0') /*until end of passwordCharacterSet is reached*/ {
      while (passwordMember < maxNrOfPasswords) {
        /*create hash*/
        i = 0; /*copy salt*/
        while (i < SALT_LEN) {
          singleHash[i] = passwordData[passwordMember].salt[i];
          i++;
        }
        singleHash[10] = '|'; /*delimeter is after salt*/
        singleHash[11] = * p1; /*after the delimeter the passwords gets appended*/

        if (passwordData[passwordMember].algorithm == HASH_ALG_SHA1 && ((passwordData[passwordMember].password == NULL && memberJump == 0) || memberJump != 0)) {
          /*get hash SHA1*/
          cH1 = SHA1(singleHash, hashArraySize, cH1); /*cH1 points now to the calc. hash*/
          /*try on member*/
          passwordMemberReset = passwordMember; /*remember where we started*/
          do /*looped ehre in order to get better performance by comparing in the same salt/algo group*/ {
            if (compareHash(passwordData[passwordMember].hash, calcHash1, HASH_ALG_SHA1)) {
              password = (char * ) malloc(sizeof(char) * 2); /*allocs two char: one for password and one for '\0'*/
              if (password == NULL) {
                return FALSE;
              }
              * password = * p1;
              password[1] = '\0';
              passwordData[passwordMember].password = password;
              cracked++;
              if (cracked == maxNrOfPasswords) /*all possible passwords are found.*/ {
                tried++;
                printf("Tried %ld passwords, %d cracked\n", tried, cracked);
                return TRUE;
              }
            }
            /*checks if we have more passwords in the same salt/algo group*/
            if (passwordMember + 1 < maxNrOfPasswords && passwordData[passwordMember].algorithm == passwordData[passwordMember + 1].algorithm &&
              cmpSalts(passwordData[passwordMember].salt, passwordData[passwordMember + 1].salt)) {
              passwordMember++;
              if (memberJump < passwordMember) /*maximum size of people with same salt and algo*/ {
                memberJump = passwordMember;
              }
              flag = 1; /*there are more members in the same group of salt and algo*/
            } else {
              flag = 0; /*single passwords in single group*/
            }
          }
          while (flag == 1 && passwordMember < maxNrOfPasswords);
          passwordMember = passwordMemberReset;
        } else if ((passwordData[passwordMember].password == NULL && memberJump == 0) || memberJump != 0) /*SHA256 was used*/ {
          /*get hash SHA256*/
          cH2 = SHA256(singleHash, hashArraySize, cH2); /*12 is the size of salt + '|' + passwdrd*/
          /*try on member*/
          passwordMemberReset = passwordMember;
          do /*looped ehre in order to get better performance by comparing in the same salt/algo group*/ {
            if (compareHash(passwordData[passwordMember].hash, calcHash2, HASH_ALG_SHA256)) {
              password = (char * ) malloc(sizeof(char) * 2);
              if (password == NULL) {
                return FALSE;
              }
              * password = * p1;
              password[1] = '\0';
              passwordData[passwordMember].password = password;
              cracked++;
              if (cracked == maxNrOfPasswords) /*maximum size of people with same salt and algo*/ {
                tried++;
                printf("Tried %ld passwords, %d cracked\n", tried, cracked);
                return TRUE;
              }
            }
            /*checks if we have more passwords in the same salt/algo group*/
            if (passwordMember + 1 < maxNrOfPasswords && passwordData[passwordMember].algorithm == passwordData[passwordMember + 1].algorithm &&
              cmpSalts(passwordData[passwordMember].salt, passwordData[passwordMember + 1].salt)) {
              passwordMember++;
              if (memberJump < passwordMember) {
                memberJump = passwordMember;
              }
              flag = 1;
            } else {
              flag = 0;
            }
          }
          while (flag == 1 && passwordMember < maxNrOfPasswords);
          passwordMember = passwordMemberReset;
        }
        if (memberJump != 0) {
          passwordMember = memberJump + 1;
          memberJump = 0;
        } else {
          passwordMember++;
        }
      }
      tried++;
      if (tried % DUMP_COUNT == 0) {
        printf("%ld: %c (%d found)\n", tried, * p1, cracked);
      }
      passwordMember = 0;
      p1++;
    }
  }
  passwordMember = 0;
  hashArraySize++;
  if (minLen <= 2 && maxLen >= 2) /*here only two digit passwords are tested*/ {
    p1 = passwordCharacterSet;
    p2 = passwordCharacterSet;
    while ( * p2 != '\0') {
      while ( * p1 != '\0') {
        while (passwordMember < maxNrOfPasswords) {
          /*create hash*/
          i = 0;
          while (i < SALT_LEN) {
            twoHash[i] = passwordData[passwordMember].salt[i];
            i++;
          }
          twoHash[10] = '|';
          twoHash[11] = * p2;
          twoHash[12] = * p1;
          if (passwordData[passwordMember].algorithm == HASH_ALG_SHA1 && ((passwordData[passwordMember].password == NULL && memberJump == 0) || memberJump != 0)) {
            /*get hash SHA1*/
            cH1 = SHA1(twoHash, hashArraySize, cH1); /*13 is the size of salt + '|' + passwdrd*/
            /*try on member*/
            passwordMemberReset = passwordMember;
            do {
              if (compareHash(passwordData[passwordMember].hash, calcHash1, HASH_ALG_SHA1)) {
                password = (char * ) malloc(sizeof(char) * 3);
                if (password == NULL) {
                  return FALSE;
                }
                password[0] = * p2;
                password[1] = * p1;
                password[2] = '\0';
                passwordData[passwordMember].password = password;
                cracked++;
                if (cracked == maxNrOfPasswords) {
                  tried++;
                  printf("Tried %ld passwords, %d cracked\n", tried, cracked);
                  return TRUE;
                }
              }

              if (passwordMember + 1 < maxNrOfPasswords && passwordData[passwordMember].algorithm == passwordData[passwordMember + 1].algorithm &&
                cmpSalts(passwordData[passwordMember].salt, passwordData[passwordMember + 1].salt)) {
                passwordMember++;
                if (memberJump < passwordMember) /*maximum size of people with same salt and algo*/ {
                  memberJump = passwordMember;
                }
                flag = 1;
              } else {
                flag = 0;
              }
            }
            while (flag == 1 && passwordMember < maxNrOfPasswords);
            passwordMember = passwordMemberReset;
          } else if ((passwordData[passwordMember].password == NULL && memberJump == 0) || memberJump != 0) {
            /*get hash SHA256*/
            cH2 = SHA256(twoHash, hashArraySize, cH2); /*13 is the size of salt + '|' + passwdrd*/
            /*try on member*/
            passwordMemberReset = passwordMember;
            do {
              if (compareHash(passwordData[passwordMember].hash, calcHash2, HASH_ALG_SHA256)) {
                password = (char * ) malloc(sizeof(char) * 3);
                if (password == NULL) {
                  return FALSE;
                }
                password[0] = * p2;
                password[1] = * p1;
                password[2] = '\0';
                passwordData[passwordMember].password = password;
                cracked++;
                if (cracked == maxNrOfPasswords) {
                  tried++;
                  printf("Tried %ld passwords, %d cracked\n", tried, cracked);
                  return TRUE;
                }
              }
              if (passwordMember + 1 < maxNrOfPasswords && passwordData[passwordMember].algorithm == passwordData[passwordMember + 1].algorithm &&
                cmpSalts(passwordData[passwordMember].salt, passwordData[passwordMember + 1].salt)) {
                passwordMember++;
                if (memberJump < passwordMember) {
                  memberJump = passwordMember;
                }
                flag = 1;
              } else {
                flag = 0;
              }
            }
            while (flag == 1 && passwordMember < maxNrOfPasswords);
            passwordMember = passwordMemberReset;
          }
          if (memberJump != 0) {
            passwordMember = memberJump + 1;
            memberJump = 0;
          } else {
            passwordMember++;
          }
        }
        tried++;
        if (tried % DUMP_COUNT == 0) {
          printf("%ld: %c%c (%d found)\n", tried, * p2, * p1, cracked);
        }
        passwordMember = 0;
        p1++;
      }
      p1 = passwordCharacterSet;
      p2++;
    }
  }
  passwordMember = 0;
  hashArraySize++;
  if (minLen <= 3 && maxLen >= 3) /*here only three digit passwords are tested*/ {
    p1 = passwordCharacterSet;
    p2 = passwordCharacterSet;
    p3 = passwordCharacterSet;

    while ( * p3 != '\0') {
      while ( * p2 != '\0') {
        while ( * p1 != '\0') {
          while (passwordMember < maxNrOfPasswords) {
            /*create hash*/
            i = 0;
            while (i < SALT_LEN) {
              threeHash[i] = passwordData[passwordMember].salt[i];
              i++;
            }
            threeHash[10] = '|';
            threeHash[11] = * p3;
            threeHash[12] = * p2;
            threeHash[13] = * p1;
            if (passwordData[passwordMember].algorithm == HASH_ALG_SHA1 && ((passwordData[passwordMember].password == NULL && memberJump == 0) || memberJump != 0)) {
              /*get hash SHA1*/
              cH1 = SHA1(threeHash, hashArraySize, cH1); /*14 is the size of salt + '|' + passwdrd*/
              /*try on member*/
              passwordMemberReset = passwordMember;
              do {
                if (compareHash(passwordData[passwordMember].hash, calcHash1, HASH_ALG_SHA1)) {
                  password = (char * ) malloc(sizeof(char) * 4);
                  if (password == NULL) {
                    return FALSE;
                  }
                  password[0] = * p3;
                  password[1] = * p2;
                  password[2] = * p1;
                  password[3] = '\0';
                  passwordData[passwordMember].password = password;
                  cracked++;
                  if (cracked == maxNrOfPasswords) {
                    tried++;
                    printf("Tried %ld passwords, %d cracked\n", tried, cracked);
                    return TRUE;
                  }
                }

                if (passwordMember + 1 < maxNrOfPasswords && passwordData[passwordMember].algorithm == passwordData[passwordMember + 1].algorithm &&
                  cmpSalts(passwordData[passwordMember].salt, passwordData[passwordMember + 1].salt)) {
                  passwordMember++;
                  if (memberJump < passwordMember) /*maximum size of people with same salt and algo*/ {
                    memberJump = passwordMember;
                  }
                  flag = 1;
                } else {
                  flag = 0;
                }
              }
              while (flag == 1 && passwordMember < maxNrOfPasswords);
              passwordMember = passwordMemberReset;
            } else if ((passwordData[passwordMember].password == NULL && memberJump == 0) || memberJump != 0) {
              /*get hash SHA256*/
              cH2 = SHA256(threeHash, hashArraySize, cH2); /*14 is the size of salt + '|' + passwdrd*/
              /*try on member*/
              passwordMemberReset = passwordMember;
              do {
                if (compareHash(passwordData[passwordMember].hash, calcHash2, HASH_ALG_SHA256)) {
                  password = (char * ) malloc(sizeof(char) * 4);
                  if (password == NULL) {
                    return FALSE;
                  }
                  password[0] = * p3;
                  password[1] = * p2;
                  password[2] = * p1;
                  password[3] = '\0';
                  passwordData[passwordMember].password = password;
                  cracked++;
                  if (cracked == maxNrOfPasswords) {
                    tried++;
                    printf("Tried %ld passwords, %d cracked\n", tried, cracked);
                    return TRUE;
                  }
                }
                if (passwordMember + 1 < maxNrOfPasswords && passwordData[passwordMember].algorithm == passwordData[passwordMember + 1].algorithm &&
                  cmpSalts(passwordData[passwordMember].salt, passwordData[passwordMember + 1].salt)) {
                  passwordMember++;
                  if (memberJump < passwordMember) {
                    memberJump = passwordMember;
                  }
                  flag = 1;
                } else {
                  flag = 0;
                }
              }
              while (flag == 1 && passwordMember < maxNrOfPasswords);
              passwordMember = passwordMemberReset;
            }
            if (memberJump != 0) {
              passwordMember = memberJump + 1;
              memberJump = 0;
            } else {
              passwordMember++;
            }
          }
          tried++;
          if (tried % DUMP_COUNT == 0) {
            printf("%ld: %c%c%c (%d found)\n", tried, * p3, * p2, * p1, cracked);
          }
          passwordMember = 0;
          p1++;
        }
        p1 = passwordCharacterSet;
        p2++;
      }
      p1 = passwordCharacterSet;
      p2 = passwordCharacterSet;
      p3++;
    }
  }
  passwordMember = 0;
  hashArraySize++;
  if (minLen <= 4 && maxLen >= 4) /*here only four digit passwords are tested*/ {
    p1 = passwordCharacterSet;
    p2 = passwordCharacterSet;
    p3 = passwordCharacterSet;
    p4 = passwordCharacterSet;
    while ( * p4 != '\0') {
      while ( * p3 != '\0') {
        while ( * p2 != '\0') {
          while ( * p1 != '\0') {
            while (passwordMember < maxNrOfPasswords) {
              /*create hash*/
              i = 0;
              while (i < SALT_LEN) {
                fourHash[i] = passwordData[passwordMember].salt[i];
                i++;
              }
              fourHash[10] = '|';
              fourHash[11] = * p4;
              fourHash[12] = * p3;
              fourHash[13] = * p2;
              fourHash[14] = * p1;
              if (passwordData[passwordMember].algorithm == HASH_ALG_SHA1 && ((passwordData[passwordMember].password == NULL && memberJump == 0) || memberJump != 0)) {
                /*get hash SHA1*/
                cH1 = SHA1(fourHash, hashArraySize, cH1); /*15 is the size of salt + '|' + passwdrd*/
                /*try on member*/
                passwordMemberReset = passwordMember;
                do {
                  if (compareHash(passwordData[passwordMember].hash, calcHash1, HASH_ALG_SHA1)) {
                    password = (char * ) malloc(sizeof(char) * 5);
                    if (password == NULL) {
                      return FALSE;
                    }
                    password[0] = * p4;
                    password[1] = * p3;
                    password[2] = * p2;
                    password[3] = * p1;
                    password[4] = '\0';
                    passwordData[passwordMember].password = password;
                    cracked++;
                    if (cracked == maxNrOfPasswords) {
                      tried++;
                      printf("Tried %ld passwords, %d cracked\n", tried, cracked);
                      return TRUE;
                    }
                  }

                  if (passwordMember + 1 < maxNrOfPasswords && passwordData[passwordMember].algorithm == passwordData[passwordMember + 1].algorithm &&
                    cmpSalts(passwordData[passwordMember].salt, passwordData[passwordMember + 1].salt)) {
                    passwordMember++;
                    if (memberJump < passwordMember) /*maximum size of people with same salt and algo*/ {
                      memberJump = passwordMember;
                    }
                    flag = 1;
                  } else {
                    flag = 0;
                  }
                }
                while (flag == 1 && passwordMember < maxNrOfPasswords);
                passwordMember = passwordMemberReset;
              } else if ((passwordData[passwordMember].password == NULL && memberJump == 0) || memberJump != 0) {
                /*get hash SHA256*/
                cH2 = SHA256(fourHash, hashArraySize, cH2); /*15 is the size of salt + '|' + passwdrd*/
                /*try on member*/
                passwordMemberReset = passwordMember;
                do {
                  if (compareHash(passwordData[passwordMember].hash, calcHash2, HASH_ALG_SHA256)) {
                    password = (char * ) malloc(sizeof(char) * 5);
                    if (password == NULL) {
                      return FALSE;
                    }
                    password[0] = * p4;
                    password[1] = * p3;
                    password[2] = * p2;
                    password[3] = * p1;
                    password[4] = '\0';
                    passwordData[passwordMember].password = password;
                    cracked++;
                    if (cracked == maxNrOfPasswords) {
                      tried++;
                      printf("Tried %ld passwords, %d cracked\n", tried, cracked);
                      return TRUE;
                    }
                  }
                  if (passwordMember + 1 < maxNrOfPasswords && passwordData[passwordMember].algorithm == passwordData[passwordMember + 1].algorithm &&
                    cmpSalts(passwordData[passwordMember].salt, passwordData[passwordMember + 1].salt)) {
                    passwordMember++;
                    if (memberJump < passwordMember) {
                      memberJump = passwordMember;
                    }
                    flag = 1;
                  } else {
                    flag = 0;
                  }
                }
                while (flag == 1 && passwordMember < maxNrOfPasswords);
                passwordMember = passwordMemberReset;
              }
              if (memberJump != 0) {
                passwordMember = memberJump + 1;
                memberJump = 0;
              } else {
                passwordMember++;
              }
            }
            tried++;
            if (tried % DUMP_COUNT == 0) {
              printf("%ld: %c%c%c%c (%d found)\n", tried, * p4, * p3, * p2, * p1, cracked);
            }
            passwordMember = 0;
            p1++;
          }
          p1 = passwordCharacterSet;
          p2++;
        }
        p1 = passwordCharacterSet;
        p2 = passwordCharacterSet;
        p3++;
      }
      p1 = passwordCharacterSet;
      p2 = passwordCharacterSet;
      p3 = passwordCharacterSet;
      p4++;
    }
  }
  passwordMember = 0;
  hashArraySize++;
  if (maxLen == 5) /*here only five digit passwords are tested*/ {
    p1 = passwordCharacterSet;
    p2 = passwordCharacterSet;
    p3 = passwordCharacterSet;
    p4 = passwordCharacterSet;
    p5 = passwordCharacterSet;
    while ( * p5 != '\0') {
      while ( * p4 != '\0') {
        while ( * p3 != '\0') {
          while ( * p2 != '\0') {
            while ( * p1 != '\0') {
              while (passwordMember < maxNrOfPasswords) {
                /*create hash*/
                i = 0;
                while (i < SALT_LEN) {
                  fiveHash[i] = passwordData[passwordMember].salt[i];
                  i++;
                }
                fiveHash[10] = '|';
                fiveHash[11] = * p5;
                fiveHash[12] = * p4;
                fiveHash[13] = * p3;
                fiveHash[14] = * p2;
                fiveHash[15] = * p1;
                if (passwordData[passwordMember].algorithm == HASH_ALG_SHA1 && ((passwordData[passwordMember].password == NULL && memberJump == 0) || memberJump != 0)) {
                  /*get hash SHA1*/
                  cH1 = SHA1(fiveHash, hashArraySize, cH1); /*16 is the size of salt + '|' + passwdrd*/
                  /*try on member*/
                  passwordMemberReset = passwordMember;
                  do {
                    if (compareHash(passwordData[passwordMember].hash, calcHash1, HASH_ALG_SHA1)) {
                      password = (char * ) malloc(sizeof(char) * 6);
                      if (password == NULL) {
                        return FALSE;
                      }
                      password[0] = * p5;
                      password[1] = * p4;
                      password[2] = * p3;
                      password[3] = * p2;
                      password[4] = * p1;
                      password[5] = '\0';
                      passwordData[passwordMember].password = password;
                      cracked++;
                      if (cracked == maxNrOfPasswords) {
                        tried++;
                        printf("Tried %ld passwords, %d cracked\n", tried, cracked);
                        return TRUE;
                      }
                    }

                    if (passwordMember + 1 < maxNrOfPasswords && passwordData[passwordMember].algorithm == passwordData[passwordMember + 1].algorithm &&
                      cmpSalts(passwordData[passwordMember].salt, passwordData[passwordMember + 1].salt)) {
                      passwordMember++;
                      if (memberJump < passwordMember) /*maximum size of people with same salt and algo*/ {
                        memberJump = passwordMember;
                      }
                      flag = 1;
                    } else {
                      flag = 0;
                    }
                  }
                  while (flag == 1 && passwordMember < maxNrOfPasswords);
                  passwordMember = passwordMemberReset;
                } else if ((passwordData[passwordMember].password == NULL && memberJump == 0) || memberJump != 0) {
                  /*get hash SHA256*/
                  cH2 = SHA256(fiveHash, hashArraySize, cH2); /*16 is the size of salt + '|' + passwdrd*/
                  /*try on member*/
                  passwordMemberReset = passwordMember;
                  do {
                    if (compareHash(passwordData[passwordMember].hash, calcHash2, HASH_ALG_SHA256)) {
                      password = (char * ) malloc(sizeof(char) * 6);
                      if (password == NULL) {
                        return FALSE;
                      }
                      password[0] = * p5;
                      password[1] = * p4;
                      password[2] = * p3;
                      password[3] = * p2;
                      password[4] = * p1;
                      password[5] = '\0';
                      passwordData[passwordMember].password = password;
                      cracked++;
                      if (cracked == maxNrOfPasswords) {
                        tried++;
                        printf("Tried %ld passwords, %d cracked\n", tried, cracked);
                        return TRUE;
                      }
                    }
                    if (passwordMember + 1 < maxNrOfPasswords && passwordData[passwordMember].algorithm == passwordData[passwordMember + 1].algorithm &&
                      cmpSalts(passwordData[passwordMember].salt, passwordData[passwordMember + 1].salt)) {
                      passwordMember++;
                      if (memberJump < passwordMember) {
                        memberJump = passwordMember;
                      }
                      flag = 1;
                    } else {
                      flag = 0;
                    }
                  }
                  while (flag == 1 && passwordMember < maxNrOfPasswords);
                  passwordMember = passwordMemberReset;
                }
                if (memberJump != 0) {
                  passwordMember = memberJump + 1;
                  memberJump = 0;
                } else {
                  passwordMember++;
                }
              }
              tried++;
              if (tried % DUMP_COUNT == 0) {
                printf("%ld: %c%c%c%c%c (%d found)\n", tried, * p5, * p4, * p3, * p2, * p1, cracked);
              }
              passwordMember = 0;
              p1++;
            }
            p1 = passwordCharacterSet;
            p2++;
          }
          p1 = passwordCharacterSet;
          p2 = passwordCharacterSet;
          p3++;
        }
        p1 = passwordCharacterSet;
        p2 = passwordCharacterSet;
        p3 = passwordCharacterSet;
        p4++;
      }
      p1 = passwordCharacterSet;
      p2 = passwordCharacterSet;
      p3 = passwordCharacterSet;
      p4 = passwordCharacterSet;
      p5++;
    }
  }
  printf("Tried %ld passwords, %d cracked\n", tried, cracked);
  return TRUE;
}
/**
 *compares two hash values if they are the same
 *return true(1) if the are the same, otherwise false(0)
 */
int compareHash(unsigned char * hash1, unsigned char * hash2, int algotype) {
  int i = 0;
  if (algotype == HASH_ALG_SHA1) /*checks algotype*/ {
    while (i < SHA_DIGEST_LENGTH) /*length of SHA1*/ {
      if (hash1[i] != hash2[i]) /*bruteforce compare of hashvalues*/ {
        return FALSE;
      }
      i++;
    }
  } else {
    while (i < SHA256_DIGEST_LENGTH) /*length of SHA256*/ {
      if (hash1[i] != hash2[i]) /*bruteforce compare of hashvalues*/ {
        return FALSE;
      }
      i++;
    }
  }
  return TRUE; /*hashes are equivalent*/
}
/**
 * sorts the given datastructure according to assignment
 * basic sorting algorithm is the bubblesort
 */
void sort(PasswordEntry * passwordData, int size) {
  /*loop variables*/
  int i = 0;
  int j = 0;
  /*helpervariable*/
  int sh2start = 0;
  PasswordEntry temp; /*used for swapping*/
  int safetycheck = 0; /*range check*/
  char * p1; /*used for string comaprisons etc.*/
  char * p2;
  unsigned char * up1; /*used for string comaprisons etc.*/
  unsigned char * up2;
  int diff = 0;
  int lowerIndex = 0; /*used for hierachical structuring*/
  int upperIndex = 0;
  int maxSizeIndexes = 0;
  int counter1 = 0;

  /*SORT BY ALGORITHM*/
  for (i = 0; i < size - 1; i++) {
    for (j = 0; j < size - i - 1; j++) {
      if (passwordData[j].algorithm > passwordData[j + 1].algorithm) {
        temp = passwordData[j];
        passwordData[j] = passwordData[j + 1];
        passwordData[j + 1] = temp;
      }
    }
  }

  while (sh2start < size && passwordData[sh2start].algorithm != HASH_ALG_SHA256) /*index of first appearence of sh2*/ {
    sh2start++;
  }

  /*SORT BY SALTS*/
  i = 0;
  j = 0;

  while (passwordData[i].algorithm == HASH_ALG_SHA1) {
    for (j = 0; j < sh2start - i - 1; j++) {
      safetycheck = 0;
      up1 = passwordData[j].salt;
      up2 = passwordData[j + 1].salt;

      while (safetycheck < SALT_LEN && * up1 == * up2) {
        safetycheck++;
        up1++;
        up2++;
      }
      if (safetycheck < SALT_LEN && * up1 > * up2) {
        temp = passwordData[j];
        passwordData[j] = passwordData[j + 1];
        passwordData[j + 1] = temp;
      }
    }
    i++;
  }
  if (sh2start < size) /*checks if we even have a sh2 coded password to sort*/ {
    while (i < size - 1) {
      for (j = sh2start; j < size - i + sh2start - 1; j++) {
        safetycheck = 0;
        up1 = passwordData[j].salt;
        up2 = passwordData[j + 1].salt;

        while (safetycheck < SALT_LEN && * up1 == * up2) {
          safetycheck++;
          up1++;
          up2++;
        }
        if (safetycheck < SALT_LEN && * up1 > * up2) {
          temp = passwordData[j];
          passwordData[j] = passwordData[j + 1];
          passwordData[j + 1] = temp;
        }
      }
      i++;
    }
  }

  /*SORT BY USERNAME in same salt and algorithm group*/
  while (upperIndex < size && cmpSalts(passwordData[lowerIndex].salt, passwordData[upperIndex].salt) && passwordData[upperIndex].algorithm == passwordData[lowerIndex].algorithm) {
    upperIndex++;
  }
  while (upperIndex < size) {

    /*Sort depending on String in lower to upper index range*/
    for (; lowerIndex < upperIndex; lowerIndex++) {
      for (j = lowerIndex + 1; j < upperIndex; j++) {
        p1 = passwordData[lowerIndex].username;
        p2 = passwordData[j].username;
        diff = 0;
        while ( * p1 != '\0' && * p2 != '\0') {
          if ( * p1 != * p2) {
            diff = * p1 - * p2;
            break;
          }
          p1++;
          p2++;
        }
        if (diff > 0 || (diff == 0 && * p1 != '\0')) {
          temp = passwordData[j];
          passwordData[j] = passwordData[lowerIndex];
          passwordData[lowerIndex] = temp;
        }
      }
    }
    /*-set the new ranges-*/
    lowerIndex = upperIndex;

    while (upperIndex < size && cmpSalts(passwordData[lowerIndex].salt, passwordData[upperIndex].salt) && passwordData[upperIndex].algorithm == passwordData[lowerIndex].algorithm) {
      upperIndex++;
    }

  }

  /*SORT BY HASHVALUE*/
  /*set new group ranges*/
  lowerIndex = 0;
  while (upperIndex < size && cmpSalts(passwordData[lowerIndex].salt, passwordData[upperIndex].salt) &&
    passwordData[upperIndex].algorithm == passwordData[lowerIndex].algorithm &&
    compareTo(passwordData[lowerIndex].username, passwordData[upperIndex].username)) {
    upperIndex++;
  }
  while (upperIndex < size) {
    if (passwordData[lowerIndex].algorithm == HASH_ALG_SHA1) {
      maxSizeIndexes = SHA_DIGEST_LENGTH;
    } else {
      maxSizeIndexes = SHA256_DIGEST_LENGTH;
    }

    for (; lowerIndex < upperIndex; lowerIndex++) {
      for (j = lowerIndex + 1; j < upperIndex; j++) {
        up1 = passwordData[lowerIndex].hash;
        up2 = passwordData[j].hash;
        diff = 0;
        while (counter1 < maxSizeIndexes) {
          if ( * up1 != * up2) {
            diff = * up1 - * up2; /*SIMPLY CALCS THE DIFFERENCE FOR LATER CHECK*/
            break; /*perforamnce booster*/
          }
          up1++;
          up2++;
          counter1++;
        }
        if (diff > 0) /*CHECKS THE DIFFERENCE, if it is positive it has to be swapped*/ {
          temp = passwordData[j];
          passwordData[j] = passwordData[lowerIndex];
          passwordData[lowerIndex] = temp;
        }
      }
    }
    /*-set new ranges-*/
    lowerIndex = upperIndex;

    while (upperIndex < size && cmpSalts(passwordData[lowerIndex].salt, passwordData[upperIndex].salt) &&
      passwordData[upperIndex].algorithm == passwordData[lowerIndex].algorithm) {
      upperIndex++;
    }

  }

}
/**
 *compares two given salt arrays of length SALT_LEN
 *return true(1) if the 2 given salts are equivalent
 *otherwise returns false(0)
 */
int cmpSalts(Salt salt1, Salt salt2) {
  int i = 0;

  while (i < SALT_LEN) {
    if (salt1[i] != salt2[i]) {
      return FALSE;
    }
    i++;
  }
  return TRUE;
}