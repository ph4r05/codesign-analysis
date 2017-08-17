#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import random


def random_isikukood():
    """
    Generates random valid Estonian Personal Identification Number
    :return:
    """

    century = random.randint(0, 1)
    sex = random.randint(3, 4)

    d1 = sex + century

    # year - century 0 -> live people.. start with 40
    #        century 1 -> adult people, none :P
    year = random.randint(50, 99)

    # generate random day & month in that year - ordinals
    minord = datetime.date(year=year, month=1, day=1).toordinal()
    maxord = datetime.date(year=year, month=12, day=31).toordinal()
    randord = random.randint(minord, maxord)
    rnddate = datetime.date.fromordinal(randord)

    serial = random.randint(0, 999)
    code = '%d%02d%02d%02d%03d' % (d1, year, rnddate.month, rnddate.day, serial)
    return code + control_nr(code)


def control_nr(code):
    code = [int(i) for i in code]
    weight1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 1]
    weight2 = [3, 4, 5, 6, 7, 8, 9, 1, 2, 3]
    sum1 = sum([x*y for x,y in zip(code, weight1)])
    sum2 = sum([x*y for x,y in zip(code, weight2)])
    if sum1 % 11 != 10:
        return str(sum1 % 11)
    elif sum2 % 11 != 10:
        return str(sum2 % 11)
    else:
        return "0"


if __name__ == '__main__':
    print(random_isikukood())

