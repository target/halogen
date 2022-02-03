# coding=utf-8
""" The render library to support all output processes  """
import datetime


def yara_print_rule(self, l):
    """ iterate over the list, and print a string for each rule
    parameter: l - list of rules"""
    if self.name:
        rname = str(self.name)
    else:
        rname = "halogen_generated_{md5_hash}".format(md5_hash=self.get_file[0])
    if self.dirhash and len(self.dirhash) < 20:
        md5val = self.dirhash
    else:
        md5val = self.get_file[0]
    if self.dir:
        dir_path = self.dir
        if "\\" in dir_path:
            win_path = dir_path.replace("\\", "\\\\")
            fname = "Directory: {0} ".format(win_path)
        else:
            fname = "Directory: {0} ".format(dir_path)
    else:
        fname = self.yara_base_file

    rule_string = """\
rule {rname} : maldoc image
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
""".format(rname=rname, md5_hash=md5val, date=str(datetime.date.today()),
           input_file=fname)
    for i in range(0, len(l)):
        rule_dict = l[i]
        ftype = rule_dict['format'].lower()
        image_hex = rule_dict['hex']
        s = "        ${ftype}_img_value_{image_name_string} = {{{image_value_str}}}\n".format(
            ftype=ftype, image_name_string=i, image_value_str=image_hex
        )
        rule_string += s

    rule_string += """
    condition:
        any of them
}"""
    print(rule_string)

def clam_print_rule(self, l):
    """ iterate over the list, and print a string for each rule
    parameter: l - list of rules"""
    rule_arr1 = []
    rule_arr2 = []
    rname = ""
    if self.name:
        if self.rprefix:
            rname = str(self.name)
    else:
        rname = "HalogenGenerated.{md5_hash}".format(md5_hash=self.get_file[0])
    if self.rprefix:
        if self.rprefix.endswith("."):
            rname = self.rprefix + rname
        else:
            rname = self.rprefix + "." + rname
    if self.dirhash and len(self.dirhash) < 20:
        md5val = self.dirhash
    else:
        md5val = self.get_file[0]
    if self.dir:
        dir_path = self.dir
        if "\\" in dir_path:
            win_path = dir_path.replace("\\", "\\\\")
            fname = "Directory: {0} ".format(win_path)
        else:
            fname = "Directory: {0} ".format(dir_path)
    else:
        fname = self.yara_base_file
    if self.container:
        container_list = [self.container]
    else:
        container_list = [
                "CL_TYPE_MSOLE2",
                "CL_TYPE_OOXML_WORD",
                "CL_TYPE_OOXML_XL",
                "CL_TYPE_OOXML_PPT",
                ]
    for container in container_list:
        ctype = container.split("_")[-1]
        rule_string = """{rname}.{ctype}.{date};Engine:81-255,Container:{container},Target:5;(""".format(rname=rname,ctype=ctype,date=datetime.datetime.now().strftime("%y%m%d"),container=container)
        j = len(l) - 1
        for i in range(0, len(l)):
            rule_string += str(i)
            if i < j:
                rule_string += "|"
            else: 
                rule_string += ");"
        for i in range(0, len(l)):
            rule_dict = l[i]
            ftype = rule_dict['format'].lower()
            image_hex = rule_dict['hex']
            s = "{image_value_str}".format(image_value_str=image_hex)
            rule_string += s
            if i < j:
                rule_string += ";"
        print(rule_string)

