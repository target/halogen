# coding=utf-8
""" The generator parser library to support all generation processes  """
import re
import binascii
import sys


def yara_image_rule_maker(self) -> dict:
    """ Yara image rule generator
    returns: rule_match_dict """
    if self.image_name is None:
        find_matches_dict = self.get_file[1]
        self.image_name = []
        for values in find_matches_dict:
            if len(values[0]) > 0:
                if values == "JPG2" and ("JPG" in self.image_name):
                    pass  #skip jpg2 because we matched on a more narrow jpg header value.
                else:
                    self.image_name.append(values)

    rule_match_dict = yara_image_generator(self)
    return rule_match_dict


def yara_image_generator(self) -> dict:
    """ puts the data in a format that we need for later in the process
     returns dict_list """
    dict_list = []
    if self.image_name is not None:
        for ftype in self.image_name:
            for match in self.get_file[1][ftype]:
                rule_data = {}
                rule_data['format'] = ftype
                if type(match) is bytes:
                    img_hex_value = binascii.hexlify(match)
                    value = (str(img_hex_value))
                    rule_data['hex'] = value[2:-1]
                elif type(match) is str:
                    rule_data['hex'] = match
                if rule_data not in dict_list:
                    dict_list.append(rule_data)
    return dict_list

