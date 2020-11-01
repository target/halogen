# coding=utf-8
""" The parser library to support all input file processing and parsing  """
import hashlib
import re


def idat(file_map):
    """if the idat option has been set (PNG_IDAT), we find the png header, and
    then find the IDAT chunk.  Grab bytes from the idat chunk onwards.
    parameter: file_map - bytes of file
    returns: matching bytes. """
    match_list = []
    png_header = re.compile(b'(?s)\x89\x50\x4e\x47')
    png_idat = re.compile(b'(?s)(\x49\x44\x41\x54.{50})')
    for match in png_header.finditer(file_map):
        end = match.end()
        match_list.append(png_idat.search(file_map, end).group())
    return match_list


def jpg_sos(file_map):
    """ if the jpg_sos option has been set (JPG_SOS), we find the jpg header,
    and then find the SOS section. Grab bytes from the sos section onwards.
    parameter: file_map - bytes of file
    returns: matching bytes. """
    match_list = []
    jpg_header = re.compile(b'(?s)\xff\xd8\xff\xe0\x00\x10')
    sos = re.compile(b'(?s)(\xff\xda.{50})')
    for match in jpg_header.finditer(file_map):
        end = match.end()
        match_list.append(sos.search(file_map, end).group())
    return match_list


def get_matches(self, file_map) -> dict:
    """get_matches returns all regex matches on a provided file.
    Because of how the image is store, RTF is the bytes of the ascii
    representation of bytes for the image file.

    parameter: file_map - bytes of file
    returns: dictionary of matching bytes per regex pattern.
    """
    get_file_dict = {}
    match_dict = {
        'GIF': re.findall(b'(?s)(\x47\x49\x46\x38\x39\x61.{80})', file_map),
        'RTF': re.findall(b'(?s)(.{20}\x35\x30\x34\x65\x34\x37\x30.{80}|.{20}\x66\x66\x64\x38\x66\x66.{80}|'
                          b'.{20}\x66\x66\x64\x38\x66\x66\x65\x30\x30\x30\x31\x30.{80})', file_map)
    }
    if self.jpgsos:
        match_dict['JPG_SOS'] = jpg_sos(file_map)
    else:
        match_dict['JPG'] = re.findall(b'(?s)(\xff\xd8\xff\xe0\x00\x10.{80})', file_map)
        match_dict['JPG2'] = re.findall(b'(?s)(\xff\xd8\xff.{80})', file_map)
    if self.idat:
        match_dict['PNG_IDAT'] = idat(file_map)
    else:
        match_dict['PNG'] = re.findall(b'(?s)(\x89\x50\x4e\x47.{82})', file_map)

    for file_type, regex_match in match_dict.items():
        if len(regex_match) > 0:
            get_file_dict[file_type] = regex_match
    return get_file_dict


def get_file_hash(self) -> tuple:
    """ Generate md5 for input file to include in the yara meta data and run regex matches
    returns: md5hash of file and the file dictionary. """
    hash_md5 = hashlib.md5()
    with open(self.yara_base_file, "rb") as f:
        file_map = f.read()
        get_file_dict = get_matches(self, file_map)
        hash_md5.update(file_map)
        return hash_md5.hexdigest(), get_file_dict

