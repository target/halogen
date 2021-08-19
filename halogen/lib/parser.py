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
    png_idat = re.compile(b'(?s)(\x49\x44\x41\x54.{80})')
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
    sos = re.compile(b'(?s)(\xff\xda.{100})')
    for match in jpg_header.finditer(file_map):
        end = match.end()
        match_list.append(sos.search(file_map, end).group())
    return match_list


def jpg_sof2sos(file_map):
    """ if the jpg_sof2sos option has been set, we find the jpg header,
    then find the SOF section.  Keeping track of that start point, we look for
    the SOS header.  We match all the bytes between those and then a few additional
    bytes of the SOS compressed data.
    parameter - file_map - bytes of file
    returns matching bytes."""
    match_list = []
    jpg_header = re.compile(b'(?s)\xff\xd8\xff\xe0\x00\x10')
    sof = re.compile(b'(?s)(\xff\xc0|\xff\xc2)')
    sos = re.compile(b'(?s)(\xff\xda.{45})')
    for match in jpg_header.finditer(file_map):
        end_header = match.end()
        start_sof = sof.search(file_map, end_header).start()
        end_sos = sos.search(file_map, start_sof).end()
        match_list.append(file_map[start_sof:end_sos])
    return match_list


def pattern_id(file_map):
    count = 0
    pattern = file_map[0:8]
    pattern2 = file_map[8:16]
    pattern3 = file_map[16:24]
    if pattern == pattern2:
        l = len(pattern)
        for i in range(0, len(file_map), l):
            if pattern == file_map[i:i+8]:
                count += 8
        return count
    elif pattern2 == pattern3:
        l = len(pattern2)
        for i in range(8, len(file_map)-8, l):
            if pattern2 == file_map[i:i+8]:
                count += 8
        return count
    else:
        return count

def jpg_jump(file_map):
    """ if the jpg_sof2sos_jump is set, we're going to essentially run the jpg_sof2sos function,
    but we're trying to identify repeated patterns in the post SOS section... this way we can
    jump over them and create the match from there. 
    parameter - file_map - bytes of the file
    returns matching bytes/pattern.
    """
    match_list = []
    jpg_header = re.compile(b'(?s)(\xff\xd8\xff\xe0|\xff\xd8\xff\xe1)')
    sof = re.compile(b'(?s)(\xff\xc0|\xff\xc2)')
    sos = re.compile(b'(?s)\xff\xda')
    jpg_footer = re.compile(b'(?s)\xff\xd9')
    for match in jpg_header.finditer(file_map):
        end_header = match.end()
        end_footer = jpg_footer.search(file_map, end_header).end()
        start_sof = sof.search(file_map, end_header, end_footer).start()
        end_sos_pointer = sos.search(file_map, start_sof, end_footer).end()
        number_colors_components = int.from_bytes((file_map[end_sos_pointer+2:end_sos_pointer+3]), byteorder='little')
        start_sos_data = end_sos_pointer + 3 + (number_colors_components * 2)
        pattern_start_spot = start_sos_data + 5
        data = file_map[pattern_start_spot:end_footer]
        jump_size = pattern_id(data)
        prefix = file_map[start_sof:pattern_start_spot].hex()
        unique_bytes = file_map[pattern_start_spot + jump_size: pattern_start_spot + jump_size + 84].hex()
        if jump_size == 0:
            match_list.append(prefix + unique_bytes)
        else:
            jump = " [ {} ] ".format(jump_size)
            match_list.append(prefix + jump + unique_bytes)
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
    elif self.sof2sos:
        match_dict['JPG_SOF2SOS'] = jpg_sof2sos(file_map)
    elif self.jump:
        match_dict['JPG_JUMP'] = jpg_jump(file_map)
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


def get_file(self) -> tuple:
    """ Generate md5 for input file to include in the yara meta data and run regex matches
    returns: md5hash of file and the file dictionary. """
    hash_md5 = hashlib.md5()
    with open(self.yara_base_file, "rb") as f:
        file_map = f.read()
        get_file_dict = get_matches(self, file_map)
        hash_md5.update(file_map)
        return hash_md5.hexdigest(), get_file_dict

