#ifndef DATETIME_H
#define DATETIME_H

struct datetime {
  int hour;
  int min;
  int sec;
  int wday;
  int mday;
  int yday;
  int mon;
  int year;
} ;

typedef long datetime_sec;

void datetime_tai();
datetime_sec datetime_untai();

#endif
