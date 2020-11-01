# coding=utf-8
""" The render library to support all output processes  """
import platform
import datetime
from logging import info, error 

DIR_CHARACTER = "/"
SYSTEM_PLATFORM = platform.system()
if SYSTEM_PLATFORM == "Windows":
    info("Windows Detected")
    DIR_CHARACTER = "\\"
elif SYSTEM_PLATFORM != ("Linux" or "Darwin"):
    error(f"Unsupported System type detected")


def yara_print_rule(self, input_list):
    """ iterate over the list, and print a string for each rule
    parameter: l - list of rules"""
    if self.name:
        rule_name = str(self.name)
    else:
        rule_name = "halo_generated_{md5_hash}".format(md5_hash=self.get_file[0])
    if self.dir_hash:
        md5val = self.dir_hash
    else:
        md5val = self.get_file[0]
    if self.dir:
        dir_path_name = ""
        if DIR_CHARACTER != "/":
            dir_path_name = self.dir
            dir_path_name.replace("\\", "\\\\")
        file_name = "Directory: {0}".format(dir_path_name)
    else:
        file_name = self.yara_base_file

    rule_string = """
rule {rule_name} : maldoc image
{{
    meta:
        tlp = "amber"
        author = "Halogen Generated Rule"
        date = "{date}"
        md5 = "{md5_hash}"
        family = "malware family"
        filename = "{input_file}"
        scope = "['detection', 'collection']"
        intel = "['']"
    strings:
""".format(rule_name=rule_name, md5_hash=md5val, date=str(datetime.date.today()),
           input_file=file_name)
    for i in range(0, len(input_list)):
        rule_dict = input_list[i]
        file_type = rule_dict['format'].lower()
        image_hex = rule_dict['hex']
        s = "        ${file_type}_img_value_{image_name_string} = {{{image_value_str}}}\n".format(
            file_type=file_type, image_name_string=i, image_value_str=image_hex
        )
        rule_string += s

    rule_string += """
    condition:
        any of them
}"""
    safe_rule_string = rule_string.replace("\\", "\\\\")
    print(safe_rule_string)
