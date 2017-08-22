#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import random


def random_isikukood():
    """
    Generates random valid Estonian Personal Identification Number
    :return:
    """
    # pick those likely alive and already having IDs
    year = random.randint(1950, 2020)
    century = (year - 1800) / 100

    sex = random.randint(1, 2)  # 1,2 for 18xx | 3,4 for 19xx | 5,6 for 20xx
    d1 = sex + 2 * century

    # generate random day & month in that year - ordinals
    minord = datetime.date(year=year, month=1, day=1).toordinal()
    maxord = datetime.date(year=year, month=12, day=31).toordinal()
    randord = random.randint(minord, maxord)
    rnddate = datetime.date.fromordinal(randord)

    serial = random.randint(0, 999)  # general serial space, not very effective though
    code = '%d%02d%02d%02d%03d' % (d1, year % 100, rnddate.month, rnddate.day, serial)
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

