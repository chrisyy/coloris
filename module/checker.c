/*
 *  Copyright (C) 2013-2014  Ying Ye, PhD Candidate, Boston University
 *  Advisor: Richard West
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define MY_CHECK_ALL	  _IOW(0, 0, long)
#define MY_CHECK_ONE	  _IOW(0, 1, long)
#define MY_CHECK_RESERVE  _IOW(0, 2, long)
#define MY_CHECK_FILE     _IOW(0, 3, long)
#define MY_CHECK_IPC      _IOW(0, 4, long)
#define MY_CHECK_HOT      _IOW(0, 5, long)


int main(void) {

  int fd = open("/proc/alloc", O_RDONLY);
  if(fd == -1) {
    printf("Fails to open\n");
    return 0;
  }

  char cmd;
  unsigned long pid;
  int flag = 1;
  do {
    cmd = getchar();
    if(cmd == '\n' || cmd == ' ') continue;

    switch(cmd) {

    case 'a':
      ioctl(fd, MY_CHECK_ALL, 0);
      break;

    case 'o':
      scanf("%ld", &pid);
      ioctl(fd, MY_CHECK_ONE, pid);
      break;

    case 'r':
      ioctl(fd, MY_CHECK_RESERVE, 0);
      break;

    case 'f':
      ioctl(fd, MY_CHECK_FILE, 0);
      break;

    case 'i':
      ioctl(fd, MY_CHECK_IPC, 0);
      break;

    case 'h':
      ioctl(fd, MY_CHECK_HOT, 0);
      break;

    case 'q':
      flag = 0;
      break;

    default:
      printf("Invalid command!\n");
    }
  } while(flag);

  close(fd);
  return 0;
}


/* vi: set et sw=2 sts=2: */
