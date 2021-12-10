#include <errno.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/timeb.h>

#define FUSE_USE_VERSION 26
#include <fuse.h>

#include "fat16.h"

char *FAT_FILE_NAME = "fat16_test.img";

/* Read the sector 'secnum' from the image to the buffer */
void sector_read(FILE *fd, unsigned int secnum, void *buffer)
{
  fseek(fd, BYTES_PER_SECTOR * secnum, SEEK_SET);
  fread(buffer, BYTES_PER_SECTOR, 1, fd);
}

/** TODO:
 * 将输入路径按“/”分割成多个字符串，并按照FAT文件名格式转换字符串
 * 输入: pathInput: char*, 输入的文件路径名, 如/home/user/m.c
 * 输出: pathDepth_ret, 文件层次深度, 如 3
 * 返回: 按FAT格式转换后的文件名字符串.
 * 
 * Hint1:假设pathInput为“/dir1/dir2/file.txt”，则将其分割成“dir1”，“dir2”，“file.txt”，
 *      每个字符串转换成长度为11的FAT格式的文件名，如“file.txt”转换成“FILE    TXT”，
 *      返回转换后的字符串数组，并将*pathDepth_ret设置为3, 转换格式在文档中有说明.
 * Hint2:可能会出现过长的字符串输入，如“/.Trash-1000”，需要自行截断字符串
 * Hint3:需要考虑.和..的情况(. 和 .. 的输入应当为 /.和/..)
 **/
char **path_split(char *pathInput, int *pathDepth_ret) {
        int i, j;
    int pathDepth = 1;

    char **paths = malloc(sizeof(char *));
    /* 代码开始 */

    int length = strlen(pathInput);
    int fileLength = 0;
    char *pathTemp = malloc(11 * sizeof(char));
    memset(pathTemp, 0x20, 11);
    int dotFlag = 0;

    for (i = 1; i < length; i++) {
        if (pathInput[i] == '/') {
            *(paths + pathDepth - 1) = pathTemp;
            pathDepth++;
            paths = realloc(paths, pathDepth * sizeof(char *));
            pathTemp = malloc(11 * sizeof(char));
            memset(pathTemp, 0x20, 11);
            fileLength = 0;
        } else if (pathInput[i] != '.') {
            if ((!dotFlag && fileLength < 8) || (dotFlag && fileLength < 11)) {
                if (pathInput[i] >= 'a' && pathInput[i] <= 'z') {
                    *(pathTemp + fileLength) = pathInput[i] - 32; //a-z to A-Z
                } else {
                    *(pathTemp + fileLength) = pathInput[i];
                }
                fileLength++;
            }
        } else {
            fileLength = 8;
            dotFlag = 1;
        }
    }
    *(paths + pathDepth - 1) = pathTemp;
    *pathDepth_ret = pathDepth;

    return paths;
    /* 代码结束 */
    /* 代码结束 */
}


/**
 * This function receieves a FAT file/directory name (DIR_Name) and decodes it
 * to its original user input name.
**/
BYTE *path_decode(BYTE *path)
{

  int i, j;
  BYTE *pathDecoded = malloc(MAX_SHORT_NAME_LEN * sizeof(BYTE));

  /* If the name consists of "." or "..", return them as the decoded path */
  if (path[0] == '.' && path[1] == '.' && path[2] == ' ')
  {
    pathDecoded[0] = '.';
    pathDecoded[1] = '.';
    pathDecoded[2] = '\0';
    return pathDecoded;
  }
  if (path[0] == '.' && path[1] == ' ')
  {
    pathDecoded[0] = '.';
    pathDecoded[1] = '\0';
    return pathDecoded;
  }

  /* Decoding from uppercase letters to lowercase letters, removing spaces,
   * inserting 'dots' in between them and verifying if they are legal */
  for (i = 0, j = 0; i < 11; i++)
  {
    if (path[i] != ' ')
    {
      if (i == 8)
        pathDecoded[j++] = '.';

      if (path[i] >= 'A' && path[i] <= 'Z')
        pathDecoded[j++] = path[i] - 'A' + 'a';
      else
        pathDecoded[j++] = path[i];
    }
  }
  pathDecoded[j] = '\0';
  return pathDecoded;
}

/**
 * Reads BPB, calculates the first sector of the root and data sections.
 * ============================================================================
 * Return
 * @fat16_ins: Structure that contains essential data about the File System (BPB,
 * first sector number of the Data Region, number of sectors in the root
 * directory and the first sector number of the Root Directory Region).
* =============================================================================
**/
FAT16 *pre_init_fat16(void)
{
  /* Opening the FAT16 image file */
  FILE *fd = fopen(FAT_FILE_NAME, "r+");

  if (fd == NULL)
  {
    fprintf(stderr, "Missing FAT16 image file!\n");
    exit(EXIT_FAILURE);
  }

  FAT16 *fat16_ins = malloc(sizeof(FAT16));

  fat16_ins->fd = fd;

  /** TODO: 
   * 初始化fat16_ins的其余成员变量
   * Hint: root directory的大小与Bpb.BPB_RootEntCnt有关，并且是扇区对齐的
  **/
  /* 代码开始 */
  fread(fat16_ins->Bpb.BS_jmpBoot, sizeof(BYTE), 3, fd);
  fread(fat16_ins->Bpb.BS_OEMName, sizeof(BYTE), 8, fd);
  fread(&fat16_ins->Bpb.BPB_BytsPerSec, sizeof(WORD), 1, fd);
  fread(&fat16_ins->Bpb.BPB_SecPerClus, sizeof(BYTE), 1, fd);
  fread(&fat16_ins->Bpb.BPB_RsvdSecCnt, sizeof(WORD), 1, fd);
  fread(&fat16_ins->Bpb.BPB_NumFATS, sizeof(BYTE), 1, fd);
  fread(&fat16_ins->Bpb.BPB_RootEntCnt, sizeof(WORD), 1, fd);
  fread(&fat16_ins->Bpb.BPB_TotSec16, sizeof(WORD), 1, fd);
  fread(&fat16_ins->Bpb.BPB_Media, sizeof(BYTE), 1, fd);
  fread(&fat16_ins->Bpb.BPB_FATSz16, sizeof(WORD), 1, fd);
  fread(&fat16_ins->Bpb.BPB_SecPerTrk, sizeof(WORD), 1, fd);
  fread(&fat16_ins->Bpb.BPB_NumHeads, sizeof(WORD), 1, fd);
  fread(&fat16_ins->Bpb.BPB_HiddSec, sizeof(DWORD), 1, fd);
  fread(&fat16_ins->Bpb.BPB_TotSec32, sizeof(DWORD), 1, fd);
  fread(&fat16_ins->Bpb.BS_DrvNum, sizeof(BYTE), 1, fd);
  fread(&fat16_ins->Bpb.BS_Reserved1, sizeof(BYTE), 1, fd);
  fread(&fat16_ins->Bpb.BS_BootSig, sizeof(BYTE), 1, fd);
  fread(&fat16_ins->Bpb.BS_VollID, sizeof(DWORD), 1, fd);
  fread(fat16_ins->Bpb.BS_VollLab, sizeof(BYTE), 11, fd);
  fread(fat16_ins->Bpb.BS_FilSysType, sizeof(BYTE), 8, fd);
  fread(fat16_ins->Bpb.Reserved2, sizeof(BYTE), 448, fd);
  fread(&fat16_ins->Bpb.Signature_word, sizeof(WORD), 1, fd);

  fat16_ins->FirstRootDirSecNum = fat16_ins->Bpb.BPB_RsvdSecCnt  + 
      fat16_ins->Bpb.BPB_FATSz16 * fat16_ins->Bpb.BPB_NumFATS;
  fat16_ins->FirstDataSector = fat16_ins->FirstRootDirSecNum + 
      fat16_ins->Bpb.BPB_RootEntCnt * 32 /fat16_ins->Bpb.BPB_BytsPerSec ;


  /* 代码结束 */

  return fat16_ins;
}


/** TODO:
 * 返回簇号为ClusterN对应的FAT表项
**/
WORD fat_entry_by_cluster(FAT16 *fat16_ins, WORD ClusterN)
{
  /* Buffer to store bytes from the image file and the FAT16 offset */ 
  BYTE sector_buffer[BYTES_PER_SECTOR];

  /* 代码开始 */
  WORD cluster;
  
  fseek(fat16_ins->fd, 
    fat16_ins->Bpb.BPB_RsvdSecCnt * fat16_ins->Bpb.BPB_BytsPerSec 
    + ClusterN * 2 / fat16_ins->Bpb.BPB_BytsPerSec * fat16_ins->Bpb.BPB_BytsPerSec
    , 0);
  fread(sector_buffer, sizeof(BYTE), fat16_ins->Bpb.BPB_BytsPerSec, fat16_ins->fd);

  if(ClusterN >= fat16_ins->Bpb.BPB_BytsPerSec / 2){
    ClusterN = ClusterN % (fat16_ins->Bpb.BPB_BytsPerSec / 2);
  }

  cluster = sector_buffer[ClusterN * 2] + 
      sector_buffer[ClusterN * 2 + 1] * 0x100;

  return cluster;  //可以修改

  /* 代码结束 */
}

/**
 * Given a cluster N, this function reads its fisrst sector, 
 * then set the value of its FAT entry and the value of its first sector of cluster.
 * ============================================================================
**/
void first_sector_by_cluster(FAT16 *fat16_ins, WORD ClusterN, WORD *FatClusEntryVal, WORD *FirstSectorofCluster, BYTE *buffer)
{
  *FatClusEntryVal = fat_entry_by_cluster(fat16_ins, ClusterN);
  *FirstSectorofCluster = ((ClusterN - 2) * fat16_ins->Bpb.BPB_SecPerClus) + fat16_ins->FirstDataSector;

  sector_read(fat16_ins->fd, *FirstSectorofCluster, buffer);
}


/**
 * Browse directory entries in root directory.
 * ==================================================================================
 * Return
 * 0, if we did find a file corresponding to the given path or 1 if we did not
**/
int find_root(FAT16 *fat16_ins, DIR_ENTRY *Root, const char *path)
{
  int i, j;
  int RootDirCnt = 1, is_eq;
  BYTE buffer[BYTES_PER_SECTOR];

  int pathDepth;
  char **paths = path_split((char *)path, &pathDepth);

  sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum, buffer);

  /* We search for the path in the root directory first */
  for (i = 1; i <= fat16_ins->Bpb.BPB_RootEntCnt; i++)
  {
    memcpy(Root, &buffer[((i - 1) * BYTES_PER_DIR) % BYTES_PER_SECTOR], BYTES_PER_DIR);

    /* If the directory entry is free, all the next directory entries are also
     * free. So this file/directory could not be found */
    if (Root->DIR_Name[0] == 0x00)
    {
      return 1;
    }

    /* Comparing strings character by character */
    is_eq = strncmp(Root->DIR_Name, paths[0], 11) == 0 ? 1 : 0;

    /* If the path is only one file (ATTR_ARCHIVE) and it is located in the
     * root directory, stop searching */
    if (is_eq && Root->DIR_Attr == ATTR_ARCHIVE)
    {
      return 0;
    }

    /* If the path is only one directory (ATTR_DIRECTORY) and it is located in
     * the root directory, stop searching */
    if (is_eq && Root->DIR_Attr == ATTR_DIRECTORY && pathDepth == 1)
    {
      return 0;
    }

    /* If the first level of the path is a directory, continue searching
     * in the root's sub-directories */
    if (is_eq && Root->DIR_Attr == ATTR_DIRECTORY)
    {
      return find_subdir(fat16_ins, Root, paths, pathDepth, 1);
    }

    /* End of bytes for this sector (1 sector == 512 bytes == 16 DIR entries)
     * Read next sector */
    if (i % 16 == 0 && i != fat16_ins->Bpb.BPB_RootEntCnt)
    {
      sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum + RootDirCnt, buffer);
      RootDirCnt++;
    }
  }

  /* We did not find anything */
  return 1;
}

/** TODO:
 * 从子目录开始查找path对应的文件或目录，找到返回0，没找到返回1，并将Dir填充为查找到的对应目录项
 * 
 * Hint1: 在find_subdir入口处，Dir应该是要查找的这一级目录的表项，需要根据其中的簇号，读取这级目录对应的扇区数据
 * Hint2: 目录的大小是未知的，可能跨越多个扇区或跨越多个簇；当查找到某表项以0x00开头就可以停止查找
 * Hint3: 需要查找名字为paths[curDepth]的文件或目录，同样需要根据pathDepth判断是否继续调用find_subdir函数
**/
int find_subdir(FAT16 *fat16_ins, DIR_ENTRY *Dir, char **paths, int pathDepth, int curDepth)
{
  int i, j, DirSecCnt = 1, DirCluCnt = 1,is_eq;
  BYTE buffer[BYTES_PER_SECTOR];
  BYTE tempName[11];

  WORD ClusterN, FatClusEntryVal, FirstSectorofCluster;
  
  ClusterN = Dir->DIR_FstClusLO;

  first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, buffer);

  /* Searching for the given path in all directory entries of Dir */
  /* 代码开始 */
  for (i = 1; buffer[BYTES_PER_DIR * (i - 1)] != 0x00; i++) {
        for (j = 0; j < 11; j++) {
            tempName[j] = buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + j];
        }
        if (strncmp(tempName, paths[curDepth], 11) == 0) {
            if (curDepth == pathDepth - 1) {
                strcpy(Dir->DIR_Name, tempName);
                Dir->DIR_Attr = buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 11];
                Dir->DIR_NTRes = buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 12];
                Dir->DIR_CrtTimeTenth = buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 13];
                Dir->DIR_CrtTime = buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 15] * 0x100 +
                                   buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 14];
                Dir->DIR_CrtDate = buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 17] * 0x100 +
                                   buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 16];
                Dir->DIR_LstAccDate =
                        buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 19] * 0x100 +
                        buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 18];
                Dir->DIR_FstClusHI =
                        buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 21] * 0x100 +
                        buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 20];
                Dir->DIR_WrtTime = buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 23] * 0x100 +
                                   buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 22];
                Dir->DIR_WrtDate = buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 25] * 0x100 +
                                   buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 24];
                Dir->DIR_FstClusLO =
                        buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 27] * 0x100 +
                        buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 26];
                Dir->DIR_FileSize =
                        buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 31] * 0x1000000 +
                        buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 30] * 0x10000 +
                        buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 29] * 0x100 +
                        buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 28];

                return 0;
            } else {
                Dir->DIR_FstClusLO = buffer[BYTES_PER_DIR * (i - 1) + 27] * 0x100 + buffer[BYTES_PER_DIR * (i - 1) + 26];

                return find_subdir(fat16_ins, Dir, paths, pathDepth, curDepth + 1);
            }
        }
        if (BYTES_PER_DIR * i - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) >= fat16_ins->Bpb.BPB_BytsPerSec) {
            sector_read(fat16_ins->fd, FirstSectorofCluster + DirSecCnt, buffer);
            DirSecCnt++;

        }
        if (DirSecCnt - fat16_ins->Bpb.BPB_SecPerClus * (DirCluCnt - 1) > fat16_ins->Bpb.BPB_SecPerClus) {
            first_sector_by_cluster(fat16_ins, FatClusEntryVal, &FatClusEntryVal, &FirstSectorofCluster, buffer);
            DirCluCnt++;

        }
    }
  
  /* 代码结束 */

  /* We did not find the given path */
  return 1;
}

/* Function: plit the path, while keep their original format 
 * ==================================================================================
 * exp: "/dir1/dir2/text"  -> {"dir1","dir2","text"}
 * ==================================================================================
*/
char **org_path_split(char *pathInput){
  int i, j;
  int pathDepth = 0;
  for (i = 0; pathInput[i] != '\0'; i++)
  {
    if (pathInput[i] == '/')
    {
      pathDepth++;
    }
  }
  char **orgPaths = (char **)malloc(pathDepth * sizeof(char *));
  const char token[] = "/";
  char *slice;

  /* Dividing the path into separated strings of file names */
  slice = strtok(pathInput, token);
  for (i = 0; i < pathDepth; i++)
  {
    orgPaths[i] = slice;
    slice = strtok(NULL, token);
  }
  return orgPaths;
}


/* Function: Add an entry according to specified sector and offset
 * ==================================================================================
 * exp: sectorNum = 1000, offset = 1*BYTES_PER_DIR 
 * The 1000th sector content before create: | Dir Entry(used)   |  Dir Entry(free)  | ... |
 * The 1000th sector content after create:  | Dir Entry(used)   | Added Entry(used) | ... |
 * ==================================================================================
*/
/** TODO:
 * 装填条目
 * 填入相应的属性值
 * 已经给出了文件名的示例，其它域由你们完成
 **/  
int dir_entry_create(FAT16 *fat16_ins,int sectorNum,int offset,char *Name, BYTE attr, WORD firstClusterNum,DWORD fileSize){
  /* Create memory buffer to store entry info */
  BYTE *entry_info = malloc(BYTES_PER_DIR*sizeof(BYTE));
  /* Fill in file name */
  memcpy(entry_info,Name,11);
  /* 代码开始 */  

  /* Fill in attr */
  memcpy(entry_info+11, &attr, 1);
  /* 代码结束 */ 

  time_t timer_s;
  time(&timer_s);
  struct tm *time_ptr = localtime(&timer_s);
  int value;

  /* Unused */ 
  memset(entry_info+12, 0, 10*sizeof(BYTE));
  
  /* 代码开始 */  
      
  /* File update time */
  /* 时间部分一定要阅读实验文档!!! */
  BYTE time_0x16;
  BYTE time_0x17;
  time_0x16 = (time_ptr->tm_sec / 2) + (time_ptr->tm_min * 32 % 0x100);
  time_0x17 = (time_ptr->tm_min * 32 / 0x100) + (time_ptr->tm_hour * 2048 / 0x100);
  memcpy(entry_info+22, &time_0x16, 1);
  memcpy(entry_info+23, &time_0x17, 1);
  

  /* File update date */
  BYTE date_0x18;
  BYTE date_0x19;
  date_0x18 = (time_ptr->tm_mday) + (time_ptr->tm_mon * 32 % 0x100);
  date_0x19 = (time_ptr->tm_mon * 32 / 0x100) + (time_ptr->tm_year - 80) * 512 / 0x100;
  memcpy(entry_info+24, &date_0x18, 1);
  memcpy(entry_info+25, &date_0x19, 1);
      
  /* First Cluster Number & File Size */
  memcpy(entry_info+26, &firstClusterNum, 2);
  memcpy(entry_info+28, &fileSize, 4);


  /* 代码结束 */ 

  /* Write the above entry to specified location */
  FILE *fd = fat16_ins->fd;
  BYTE *bufferm=malloc(BYTES_PER_DIR*sizeof(BYTE));
  fseek(fd,sectorNum*fat16_ins->Bpb.BPB_BytsPerSec+offset,SEEK_SET);
  int w_size = fwrite(entry_info,sizeof(BYTE),32,fd);
  fflush(fd);
  free(entry_info);
  return 0;
}

/* Function: Get parent directory path of a specified file 
 * ==================================================================================
 * exp: path = "dir1/dir2/texts" orgPaths = { "dir1", "dir2", "tests" }
 * Return "dir1/dir2"
 * ==================================================================================
*/
char * get_prt_path(const char *path, const char **orgPaths,int pathDepth){
  char *prtPath;
  if(pathDepth == 1){
    prtPath = (char *)malloc(2*sizeof(char));
    prtPath[0] = '/';
    prtPath[1] = '\0';
  }
  else {
    int prtPathLen = strlen(path) - strlen(orgPaths[pathDepth-1])-1;
    prtPath = (char *)malloc((prtPathLen+1)*sizeof(char));
    strncpy(prtPath, path, prtPathLen);
    prtPath[prtPathLen] = '\0';
  }
  return prtPath;
}

//------------------------------------------------------------------------------

void *fat16_init(struct fuse_conn_info *conn)
{
  struct fuse_context *context;
  context = fuse_get_context();

  return context->private_data;
}

void fat16_destroy(void *data)
{
  free(data);
}

int fat16_getattr(const char *path, struct stat *stbuf)
{
  FAT16 *fat16_ins;

  /* Gets volume data supplied in the context during the fat16_init function */
  struct fuse_context *context;
  context = fuse_get_context();
  fat16_ins = (FAT16 *)context->private_data;

  /* stbuf: setting file/directory attributes */
  memset(stbuf, 0, sizeof(struct stat));
  stbuf->st_dev = fat16_ins->Bpb.BS_VollID;
  stbuf->st_blksize = BYTES_PER_SECTOR * fat16_ins->Bpb.BPB_SecPerClus;
  stbuf->st_uid = getuid();
  stbuf->st_gid = getgid();

  if (strcmp(path, "/") == 0)
  {
    /* Root directory attributes */
    stbuf->st_mode = S_IFDIR | S_IRWXU;
    stbuf->st_size = 0;
    stbuf->st_blocks = 0;
    stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = 0;
  }
  else
  {
    /* File/Directory attributes */
    DIR_ENTRY Dir;

    int res = find_root(fat16_ins, &Dir, path);

    if (res == 0)
    {
      /* FAT-like permissions */
      if (Dir.DIR_Attr == ATTR_DIRECTORY)
      {
        stbuf->st_mode = S_IFDIR | 0755;
      }
      else
      {
        stbuf->st_mode = S_IFREG | 0755;
      }
      stbuf->st_size = Dir.DIR_FileSize;

      /* Number of blocks */
      if (stbuf->st_size % stbuf->st_blksize != 0)
      {
        stbuf->st_blocks = (int)(stbuf->st_size / stbuf->st_blksize) + 1;
      }
      else
      {
        stbuf->st_blocks = (int)(stbuf->st_size / stbuf->st_blksize);
      }

      /* Implementing the required FAT Date/Time attributes */
      struct tm t;
      memset((char *)&t, 0, sizeof(struct tm));
      t.tm_sec = Dir.DIR_WrtTime & ((1 << 5) - 1);
      t.tm_min = (Dir.DIR_WrtTime >> 5) & ((1 << 6) - 1);
      t.tm_hour = Dir.DIR_WrtTime >> 11;
      t.tm_mday = (Dir.DIR_WrtDate & ((1 << 5) - 1));
      t.tm_mon = (Dir.DIR_WrtDate >> 5) & ((1 << 4) - 1);
      t.tm_year = 80 + (Dir.DIR_WrtDate >> 9);
      stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = mktime(&t);
    }
    else
      return -ENOENT;  // no such file
  }
  return 0;
}

int fat16_readdir(const char *path, void *buffer, fuse_fill_dir_t filler,
                  off_t offset, struct fuse_file_info *fi)
{
  FAT16 *fat16_ins;
  BYTE sector_buffer[BYTES_PER_SECTOR];
  int RootDirCnt = 1, DirSecCnt = 1, DirCluCnt = 1, i, j;
  BYTE name[11];

  /* Gets volume data supplied in the context during the fat16_init function */
  struct fuse_context *context;
  context = fuse_get_context();
  fat16_ins = (FAT16 *)context->private_data;

  sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum, sector_buffer);

  if (strcmp(path, "/") == 0)
  {
    DIR_ENTRY Root;
    /** TODO:
     * 将root directory下的文件或目录通过filler填充到buffer中
     * 注意不需要遍历子目录
    **/
    /* Starts filling the requested directory entries into the buffer */
    for (i = 1; i <= fat16_ins->Bpb.BPB_RootEntCnt; i++)
    {

      /* 代码开始 */
      for (int j = 0; j < 11; j++) {
        name[j] = sector_buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (RootDirCnt - 1) + j];
      }
      strcpy(Root.DIR_Name, name);
      Root.DIR_Attr = sector_buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (RootDirCnt - 1) + 11];

      if (Root.DIR_Name[0] != 0xE5 && (Root.DIR_Attr == 0x20 || Root.DIR_Attr == 0x10)) {
          const char *filename = (const char *) path_decode(Root.DIR_Name);
          filler(buffer, filename, NULL, 0);
      }

      if (32 * i - fat16_ins->Bpb.BPB_BytsPerSec * (RootDirCnt - 1) >= BYTES_PER_SECTOR) {
          sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum + RootDirCnt, sector_buffer);
          RootDirCnt++;
      }

      /* 代码结束 */
    }
  }
  else
  {
    DIR_ENTRY Dir;
 
    /** TODO:
     * 通过find_root获取path对应的目录的目录项，
     * 然后访问该目录，将其下的文件或目录通过filler填充到buffer中，
     * 同样注意不需要遍历子目录
     * Hint: 需要考虑目录大小，可能跨扇区，跨簇
    **/

    /* Finds the first corresponding directory entry in the root directory and
     * store the result in the directory entry Dir */
    find_root(fat16_ins, &Dir, path);

    /* Calculating the first cluster sector for the given path */
    WORD ClusterN, FatClusEntryVal, FirstSectorofCluster;
    
    ClusterN = Dir.DIR_FstClusLO;

    first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);

    /* Start searching the root's sub-directories starting from Dir */

    /* 代码开始 */
    for (i = 1;; i++) {
      for (j = 0; j < 11; j++) {
          name[j] = sector_buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + j];
      }
      if (name[0] == 0x00) break;
      strcpy(Dir.DIR_Name, name);
      Dir.DIR_Attr = sector_buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + 11];

      if (Dir.DIR_Name[0] != 0xE5 && (Dir.DIR_Attr == 0x20 || Dir.DIR_Attr == 0x10)) {
          const char *filename = (const char *) path_decode(Dir.DIR_Name);
          filler(buffer, filename, NULL, 0);
      }

      if (BYTES_PER_DIR * i - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) >= fat16_ins->Bpb.BPB_BytsPerSec) {
          sector_read(fat16_ins->fd, FirstSectorofCluster + DirSecCnt, sector_buffer);
          DirSecCnt++;
      }

      if (DirSecCnt - fat16_ins->Bpb.BPB_SecPerClus * (DirCluCnt - 1) > fat16_ins->Bpb.BPB_SecPerClus) {
          first_sector_by_cluster(fat16_ins, FatClusEntryVal, &FatClusEntryVal, &FirstSectorofCluster,
                                  sector_buffer);
          if (FatClusEntryVal == 0 || FatClusEntryVal >= 0xFFF0) break;
          DirCluCnt++;
      }
    }


    /* 代码结束 */

  }
  return 0;
}


/** TODO:
 * 从path对应的文件的offset字节处开始读取size字节的数据到buffer中，并返回实际读取的字节数
 * 
 * Hint: 文件大小属性是Dir.DIR_FileSize；当offset超过文件大小时，应该返回0
**/
int fat16_read(const char *path, char *buffer, size_t size, off_t offset,
               struct fuse_file_info *fi)
{
  int i, j;
  BYTE *sector_buffer = malloc((size + offset) * sizeof(BYTE));

  /* Gets volume data supplied in the context during the fat16_init function */
  FAT16 *fat16_ins;
  struct fuse_context *context;
  context = fuse_get_context();
  fat16_ins = (FAT16 *)context->private_data;

  /* Searches for the given path */
  DIR_ENTRY Dir;
  find_root(fat16_ins, &Dir, path);

  /* 代码开始 */
  WORD FatClusEntryVal, FirstSectorofCluster;
  int DirSecCnt = 0;
  size_t readSize;

  first_sector_by_cluster(fat16_ins, Dir.DIR_FstClusLO, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);
  if (offset >= Dir.DIR_FileSize) {
    return 0;
  } else if (offset + size > Dir.DIR_FileSize) {
    readSize = Dir.DIR_FileSize - offset;
  } else {
    readSize = size;
  }

  while (offset >= fat16_ins->Bpb.BPB_SecPerClus * fat16_ins->Bpb.BPB_BytsPerSec) {
    first_sector_by_cluster(fat16_ins, FatClusEntryVal, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);
    offset = offset - fat16_ins->Bpb.BPB_SecPerClus * fat16_ins->Bpb.BPB_BytsPerSec;
  }

  while (offset >= fat16_ins->Bpb.BPB_BytsPerSec) {
    DirSecCnt++;
    offset = offset - fat16_ins->Bpb.BPB_BytsPerSec;
  }

  sector_read(fat16_ins->fd, FirstSectorofCluster + DirSecCnt, sector_buffer);

  for (i = 0; i < readSize; i++) {
    if (offset >= fat16_ins->Bpb.BPB_BytsPerSec) {
      DirSecCnt++;
      sector_read(fat16_ins->fd, FirstSectorofCluster + DirSecCnt, sector_buffer);
      offset = 0;
    }
    if (DirSecCnt >= fat16_ins->Bpb.BPB_SecPerClus) {
      first_sector_by_cluster(fat16_ins, FatClusEntryVal, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);
      DirSecCnt -= fat16_ins->Bpb.BPB_SecPerClus;
    }
    buffer[i] = sector_buffer[offset];
    offset++;
  }


  /* 代码结束 */
  free(sector_buffer);
  return size;
}

/* Function: Touch  a new file*/
int fat16_mknod(const char *path, mode_t mode, dev_t devNum){
  /* Gets volume data supplied in the context during the fat16_init function */
  FAT16 *fat16_ins;
  struct fuse_context *context;
  context = fuse_get_context();
  fat16_ins = (FAT16 *)context->private_data;
      
  /** TODO:
   * 查找新建文件的父目录，你可以使用辅助函数org_path_split和get_prt_path
   **/
  /* 代码开始 */ 
  int pathDepth;
  
  char *path_temp1 = (char*)malloc((strlen(path)+1)*sizeof(char));
  char *path_temp2 = (char*)malloc((strlen(path)+1)*sizeof(char));
  strcpy(path_temp1, path);
  strcpy(path_temp2, path);
  char **paths = path_split(path_temp1, &pathDepth);
  char **orgPaths = org_path_split(path_temp2);
  char *prtPath = get_prt_path(path, orgPaths, pathDepth); 
  /* 代码结束 */ 
       
  /** TODO:
   * 查找可用的entry，注意区分根目录和子目录
   * 下面提供了一些可能使用到的临时变量
   * 如果觉得不够用，可以自己定义更多的临时变量
   * 这块和前面有很多相似的地方，注意对照来实现
   **/  
  BYTE sector_buffer[BYTES_PER_SECTOR];
  BYTE name[11];
  DWORD sectorNum;
  int offset, i, j, findFlag = 0, RootDirCnt = 1, DirSecCnt = 1, DirCluCnt = 1;
  WORD ClusterN, FatClusEntryVal, FirstSectorofCluster;

  /* If parent directory is root */
  if (strcmp(prtPath, "/") == 0){
    DIR_ENTRY Root;
    sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum, sector_buffer);
    /* Starts searching free directory entries in root directory */ 
    /* 代码开始 */  
    for (i = 1; i <= fat16_ins->Bpb.BPB_RootEntCnt; i++){ //RootEntCnt == 512
      for (int j = 0; j < 11; j++) {
        name[j] = sector_buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (RootDirCnt - 1) + j];
      }
      strcpy(Root.DIR_Name, name);
      if (Root.DIR_Name[0] == 0xE5 || Root.DIR_Name[0] == 0x00) {
          findFlag = 1;
          sectorNum = fat16_ins->FirstRootDirSecNum + (RootDirCnt - 1);
          offset = BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (RootDirCnt - 1);
          break;
      }
      if (BYTES_PER_DIR * i - fat16_ins->Bpb.BPB_BytsPerSec * (RootDirCnt - 1) >= BYTES_PER_SECTOR) {
          sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum + RootDirCnt, sector_buffer);
          RootDirCnt++;
      }
    }

   
    /* 代码结束 */  
  }
  /* Else if parent directory is sub-directory */
  else{
    DIR_ENTRY Dir;
    find_root(fat16_ins,&Dir,prtPath);
    /* Find appropriate sector and offset to add the DIR ENTRY*/
    ClusterN = Dir.DIR_FstClusLO;
    first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);
    /* Start searching the root's sub-directories starting from Dir */
    /* 代码开始 */  
    
    for (i = 1; ; i++) {
      for (j = 0; j < 11; j++) {
        name[j] = sector_buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + j];
      }
      strcpy(Dir.DIR_Name, name);

      if (Dir.DIR_Name[0] == 0xE5 || Dir.DIR_Name[0] == 0x00) {
          findFlag = 1;
          sectorNum = fat16_ins->FirstDataSector + (DirSecCnt - 1);
          offset = BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1);
          break;
      }

      if (32 * i - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) >= fat16_ins->Bpb.BPB_BytsPerSec) {
          sector_read(fat16_ins->fd, FirstSectorofCluster + DirSecCnt, sector_buffer);
          DirSecCnt++;
      }

      if (DirSecCnt - fat16_ins->Bpb.BPB_SecPerClus * (DirCluCnt - 1) > fat16_ins->Bpb.BPB_SecPerClus) {
          first_sector_by_cluster(fat16_ins, FatClusEntryVal, &FatClusEntryVal, &FirstSectorofCluster,
                                  sector_buffer);
          DirCluCnt++;
      }
    }

      
    /* 代码结束 */     
  }
  /* Add the DIR ENTRY */
  if (findFlag == 1)
    dir_entry_create(fat16_ins, sectorNum, offset, paths[pathDepth-1], ATTR_ARCHIVE, 0xffff, 0);
  return 0;
}

/**
 * free cluster 时，只修改FAT对应表项
 * @return 下一个簇的簇号
  */
int freeCluster(FAT16 *fat16_ins, int ClusterNum){
  BYTE sector_buffer[BYTES_PER_SECTOR];
  WORD FATClusEntryval,FirstSectorofCluster;
  first_sector_by_cluster(fat16_ins,ClusterNum,&FATClusEntryval,&FirstSectorofCluster,sector_buffer);

  FILE *fd = fat16_ins->fd;
  /** TODO:
   * 修改FAT表
   * 注意两个表都要修改
   **/
   /* 代码开始 */
  
  fseek(fd, 
    fat16_ins->Bpb.BPB_RsvdSecCnt * fat16_ins->Bpb.BPB_BytsPerSec 
    + ClusterNum * 2 / fat16_ins->Bpb.BPB_BytsPerSec * fat16_ins->Bpb.BPB_BytsPerSec
    , 0);//FAT 1
  fread(sector_buffer, sizeof(BYTE), fat16_ins->Bpb.BPB_BytsPerSec, fd);
  if(ClusterNum >= fat16_ins->Bpb.BPB_BytsPerSec / 2){
    ClusterNum = ClusterNum % (fat16_ins->Bpb.BPB_BytsPerSec / 2);
  }
  sector_buffer[ClusterNum * 2] = 0;
  sector_buffer[ClusterNum * 2 + 1] = 0;
  fwrite(sector_buffer, sizeof(BYTE), BYTES_PER_SECTOR, fd);

  fseek(fd, 
    fat16_ins->Bpb.BPB_RsvdSecCnt * fat16_ins->Bpb.BPB_BytsPerSec +  fat16_ins->Bpb.BPB_FATSz16 * fat16_ins->Bpb.BPB_BytsPerSec
    + ClusterNum * 2 / fat16_ins->Bpb.BPB_BytsPerSec * fat16_ins->Bpb.BPB_BytsPerSec
    , 0);//FAT 2
  fread(sector_buffer, sizeof(BYTE), fat16_ins->Bpb.BPB_BytsPerSec, fd);
  if(ClusterNum >= fat16_ins->Bpb.BPB_BytsPerSec / 2){
    ClusterNum = ClusterNum % (fat16_ins->Bpb.BPB_BytsPerSec / 2);
  }
  sector_buffer[ClusterNum * 2] = 0;
  sector_buffer[ClusterNum * 2 + 1] = 0;
  fwrite(sector_buffer, sizeof(BYTE), BYTES_PER_SECTOR, fd);

   /* 代码结束 */  
  return FATClusEntryval; 
}

/* Function: remove a file */
int fat16_unlink(const char *path){
  /* Gets volume data supplied in the context during the fat16_init function */
  FAT16 *fat16_ins;
  struct fuse_context *context;
  context = fuse_get_context();
  fat16_ins = (FAT16 *)context->private_data;

  /** TODO:
   * 回收该文件所占有的簇
   * 注意完善并使用freeCluster函数
   **/
  WORD ClusterN, N;
  DIR_ENTRY Dir;
  //释放使用过的簇
  if(find_root(fat16_ins,&Dir,path) == 1){
    return 1;
  }
  ClusterN = Dir.DIR_FstClusLO;
  /* 代码开始 */ 

  /* 在完善了freeCluster函数后，此处代码量很小*/
  /* 你也可以不使用freeCluster函数，通过自己的方式实现 */
  N = ClusterN;
  do{
    freeCluster(fat16_ins, N);
  }while(N = fat_entry_by_cluster(fat16_ins, N));
  /* 代码结束 */ 
    
    
    
  /* Find the location(sector number & offset) of file entry */
  /** TODO:
   * 查找新建文件的父目录，你可以使用辅助函数org_path_split和get_prt_path
   * 这部分内容和mknode函数差不多
   **/
  /* 代码开始 */ 
  int pathDepth;
  
  char *path_temp1 = (char*)malloc((strlen(path)+1)*sizeof(char));
  char *path_temp2 = (char*)malloc((strlen(path)+1)*sizeof(char));
  strcpy(path_temp1, path);
  strcpy(path_temp2, path);
  char **paths = path_split(path_temp1, &pathDepth);
  char **orgPaths = org_path_split(path_temp2);
  char *prtPath = get_prt_path(path, orgPaths, pathDepth); 

  /* 代码结束 */ 
  
  /** TODO:
   * 定位文件在父目录中的entry，注意区分根目录和子目录
   * 下面提供了一些可能使用到的临时变量
   * 如果觉得不够用，可以自己定义更多的临时变量
   * 这块和前面有很多相似的地方，注意对照来实现
   * 流程类似，大量代码都和mknode一样，注意复用
   **/  

  BYTE sector_buffer[BYTES_PER_SECTOR];
  BYTE name[11];
  DWORD sectorNum;
  int offset, i, j, findFlag = 0, RootDirCnt = 1, DirSecCnt = 1, DirCluCnt = 1;
  WORD FatClusEntryVal, FirstSectorofCluster;

  /* If parent directory is root */
  if (strcmp(prtPath, "/") == 0){
    DIR_ENTRY Root;
    sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum, sector_buffer);
    /* Starts searching the directory entry in root directory */
    /* 代码开始 */  

    for (i = 1; i <= fat16_ins->Bpb.BPB_RootEntCnt; i++){ //RootEntCnt == 512
      for (int j = 0; j < 11; j++) {
        name[j] = sector_buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (RootDirCnt - 1) + j];
      }
      strcpy(Root.DIR_Name, name);
      if (strncmp(name, paths[pathDepth - 1], 11) == 0) {
          findFlag = 1;
          sectorNum = fat16_ins->FirstRootDirSecNum + (RootDirCnt - 1);
          offset = BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (RootDirCnt - 1);
          break;
      }
      if (BYTES_PER_DIR * i - fat16_ins->Bpb.BPB_BytsPerSec * (RootDirCnt - 1) >= BYTES_PER_SECTOR) {
          sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum + RootDirCnt, sector_buffer);
          RootDirCnt++;
      }
    }
         
      
    /* 代码结束 */  
  }  
  /* Else if parent directory is sub-directory */
  else{
    DIR_ENTRY Dir;
    find_root(fat16_ins,&Dir,prtPath);
    ClusterN = Dir.DIR_FstClusLO;
    first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);
    /* Start searching the root's sub-directories starting from Dir */
    /* 代码开始 */  
      
    for (i = 1; ; i++) {
      for (j = 0; j < 11; j++) {
        name[j] = sector_buffer[BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) + j];
      }
      strcpy(Dir.DIR_Name, name);

      if (strncmp(name, paths[pathDepth - 1], 11) == 0) {
          findFlag = 1;
          sectorNum = fat16_ins->FirstDataSector + (DirSecCnt - 1);
          offset = BYTES_PER_DIR * (i - 1) - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1);
          break;
      }

      if (32 * i - fat16_ins->Bpb.BPB_BytsPerSec * (DirSecCnt - 1) >= fat16_ins->Bpb.BPB_BytsPerSec) {
          sector_read(fat16_ins->fd, FirstSectorofCluster + DirSecCnt, sector_buffer);
          DirSecCnt++;
      }

      if (DirSecCnt - fat16_ins->Bpb.BPB_SecPerClus * (DirCluCnt - 1) > fat16_ins->Bpb.BPB_SecPerClus) {
          first_sector_by_cluster(fat16_ins, FatClusEntryVal, &FatClusEntryVal, &FirstSectorofCluster,
                                  sector_buffer);
          DirCluCnt++;
      }
    }
          
    /* 代码结束 */ 
  }
  
  /** TODO:
   * 删除文件，对相应entry做标记
   * 思考要修改entry中的哪些域
   **/
  
  /* Update file entry, change its first byte of file name to 0xe5 */
  if (findFlag == 1){
    FILE *fd = fat16_ins->fd;
    /* 代码开始 */  
    BYTE DeleteCode = 0xE5;
    fseek(fd, sectorNum * fat16_ins->Bpb.BPB_BytsPerSec + offset, SEEK_SET);
    fwrite(&DeleteCode, sizeof(BYTE), 1, fd);
    
    /* 代码结束 */ 
    fflush(fd);
  }
  return 0;
}
//------------------------------------------------------------------------------

struct fuse_operations fat16_oper = {
    .init = fat16_init,
    .destroy = fat16_destroy,
    .getattr = fat16_getattr,
    .readdir = fat16_readdir,
    .read = fat16_read,
    .mknod = fat16_mknod,
    .unlink = fat16_unlink
    };

//------------------------------------------------------------------------------


void test_path_split() {
  printf("#1 running %s\n", __FUNCTION__);

  char s[][32] = {"/texts", "/dir1/dir2/file.txt", "/.Trash-100"};
  int dr[] = {1, 3, 1};
  char sr[][3][32] = {{"TEXTS      "}, {"DIR1       ", "DIR2       ", "FILE    TXT"}, {"        TRA"}};

  int i, j, r;
  for (i = 0; i < sizeof(dr) / sizeof(dr[0]); i++) {
  
    char **ss = path_split(s[i], &r);
    assert(r == dr[i]);
    for (j = 0; j < dr[i]; j++) {
      assert(strcmp(sr[i][j], ss[j]) == 0);
      free(ss[j]);
    }
    free(ss);
    printf("test case %d: OK\n", i + 1);
  }

  printf("success in %s\n\n", __FUNCTION__);
}

void test_path_decode() {
  printf("#2 running %s\n", __FUNCTION__);

  char s[][32] = {"..        ", "FILE    TXT", "ABCD    RM "};
  char sr[][32] = {"..", "file.txt", "abcd.rm"};

  int i, j, r;
  for (i = 0; i < sizeof(s) / sizeof(s[0]); i++) {
    char *ss = (char *) path_decode(s[i]);
    assert(strcmp(ss, sr[i]) == 0);
    free(ss);
    printf("test case %d: OK\n", i + 1);
  }

  printf("success in %s\n\n", __FUNCTION__);
}

void test_pre_init_fat16() {
  printf("#3 running %s\n", __FUNCTION__);

  FAT16 *fat16_ins = pre_init_fat16();

  assert(fat16_ins->Bpb.BPB_RsvdSecCnt == 4);
  assert(fat16_ins->FirstRootDirSecNum == 124);
  assert(fat16_ins->FirstDataSector == 156);
  //assert(fat16_ins->Bpb.BPB_RsvdSecCnt == 4);
  assert(fat16_ins->Bpb.BPB_RootEntCnt == 512);
  assert(fat16_ins->Bpb.BS_BootSig == 41);
  assert(fat16_ins->Bpb.BS_VollID == 1576933109);
  assert(fat16_ins->Bpb.Signature_word == 43605);
  
  fclose(fat16_ins->fd);
  free(fat16_ins);
  
  printf("success in %s\n\n", __FUNCTION__);
}

void test_fat_entry_by_cluster() {
  printf("#4 running %s\n", __FUNCTION__);

  FAT16 *fat16_ins = pre_init_fat16();

  int cn[] = {1, 2, 4};
  int ce[] = {65535, 0, 65535};

  int i;
  for (i = 0; i < sizeof(cn) / sizeof(cn[0]); i++) {
    int r = fat_entry_by_cluster(fat16_ins, cn[i]);
    assert(r == ce[i]);
    printf("test case %d: OK\n", i + 1);
  }
  
  fclose(fat16_ins->fd);
  free(fat16_ins);

  printf("success in %s\n\n", __FUNCTION__);
}

void test_find_root() {
  printf("#5 running %s\n", __FUNCTION__);

  FAT16 *fat16_ins = pre_init_fat16();

  char path[][32] = {"/dir1", "/makefile", "/log.c"};
  char names[][32] = {"DIR1       ", "MAKEFILE   ", "LOG     C  "};
  int others[][3] = {{100, 4, 0}, {100, 8, 226}, {100, 3, 517}};

  int i;
  for (i = 0; i < sizeof(path) / sizeof(path[0]); i++) {
    DIR_ENTRY Dir;
    find_root(fat16_ins, &Dir, path[i]);
    assert(strncmp(Dir.DIR_Name, names[i], 11) == 0);
    assert(Dir.DIR_CrtTimeTenth == others[i][0]);
    assert(Dir.DIR_FstClusLO == others[i][1]);
    assert(Dir.DIR_FileSize == others[i][2]);

    printf("test case %d: OK\n", i + 1);
  }
  
  fclose(fat16_ins->fd);
  free(fat16_ins);

  printf("success in %s\n\n", __FUNCTION__);
}

void test_find_subdir() {
  printf("#6 running %s\n", __FUNCTION__);

  FAT16 *fat16_ins = pre_init_fat16();

  char path[][32] = {"/dir1/dir2", "/dir1/dir2/dir3", "/dir1/dir2/dir3/test.c"};
  char names[][32] = {"DIR2       ", "DIR3       ", "TEST    C  "};
  int others[][3] = {{100, 5, 0}, {0, 6, 0}, {0, 7, 517}};

  int i;
  for (i = 0; i < sizeof(path) / sizeof(path[0]); i++) {
    DIR_ENTRY Dir;
    find_root(fat16_ins, &Dir, path[i]);
    assert(strncmp(Dir.DIR_Name, names[i], 11) == 0);
    assert(Dir.DIR_CrtTimeTenth == others[i][0]);
    assert(Dir.DIR_FstClusLO == others[i][1]);
    assert(Dir.DIR_FileSize == others[i][2]);

    printf("test case %d: OK\n", i + 1);
  }
  /*
  char f1[]="/black";
  fat16_mknod(f1, 0, 0,fat16_ins);
  char f2[]="/dir1/white";
  fat16_mknod(f2, 0, 0,fat16_ins);
  fat16_unlink(f2, fat16_ins);
  */
  fclose(fat16_ins->fd);
  free(fat16_ins);
  printf("success in %s\n\n", __FUNCTION__);
}


int main(int argc, char *argv[])
{
  int ret;

  if (strcmp(argv[1], "--test") == 0) {
    printf("--------------\nrunning test\n--------------\n");
    FAT_FILE_NAME = "fat16_test.img";
    test_path_split();
    test_path_decode();
    test_pre_init_fat16();
    test_fat_entry_by_cluster();
    test_find_root();
    test_find_subdir();
    exit(EXIT_SUCCESS);
  }

  /* Starting a pre-initialization of the FAT16 volume */
  FAT16 *fat16_ins = pre_init_fat16();

  ret = fuse_main(argc, argv, &fat16_oper, fat16_ins);

  return ret;
}

