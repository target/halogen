![Halogen](/images/halogen.png) 
****
Halogen is a tool to automate the creation of yara rules based on the image files embedded within a malicious document. This can assist cyber security professionals in writing detection rules for malicious threats as well as help responders in identifying with particular threat they are dealing with. Currently, Halogen is able to create rules based on JPG and PNG files. 
****
![Halogen Walkthrough](/images/halo_diagram.png)

## Halogen help 
```
python3 halogen.py -h
usage: halogen.py [-h] [-f FILE] [-d DIR] [-n NAME] [--png-idat] [--jpg-sos] [--jpg-sof2sos] [--jpg-jump] [-c CONTAINER] [--clam] [--rprefix RPREFIX]

Halogen: Automatically create yara rules based on images embedded in office documents.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File to parse
  -d DIR, --directory DIR
                        directory to scan for image files.
  -n NAME, --rule-name NAME
                        specify a custom name for the rule file
  --png-idat            For PNG matches, instead of starting with the PNG file header, start with the IDAT chunk.
  --jpg-sos             For JPG matches, skip over the header and look for the Start of Scan marker, and begin the match there.
  --jpg-sof2sos         for JPG matches, skip over the header and match the SOF all the way to the SOS + 45 bytes of the data within the SOS.
  --jpg-jump            for JPG matches, skip over the header and identify the sof, the sos and then read the actual image data take that data and look for repeated bytes. Skip those bytes and then
                        create 45 bytes of raw image data.
  -c CONTAINER, --container CONTAINER
                        specify a clamav container type defaults to CL_TYPE_MSOLE2, CL_TYPE_OOXML_WORD, CL_TYPE_OOXML_XL, CL_TYPE_OOXML_PPT
  --clam                generate a clam rule instead of a yara rule
  --rprefix RPREFIX     specify a clamav ruleset prefix


```
## Testing it out
We've included some test document files with embedded images for you to test this out with.  Running `python3 halogen/halogen.py -d tests/ > /tmp/halogen_test.yara` will produce the test yara file containing all images found within the files inside the `tests/` directory.  
From here you can run `yara -s /tmp/halogen_test.yara tests/` and observe which images match which files. 

### Notes
1. We use two patterns for JPG matching.  One is less strict than the typical JPG file header, and we use this because we've seen some malicious files match this pattern.  If Halogen finds both, it'll default to writing out the more strict match.  Typically, these have the same matching content, so no detection really gets missed. 
2. For PNG files you can choose to start by default at the file header, or with `--png-idat` you can start at the IDAT chunk found within a PNG file.  We also reduced the bytes returned when matching on the IDAT chunk. 
3. Similar to the above, you can start JPG matches at the Start of Scan marker by using the `--jpg-sos` flag.
4. Because of how the SOS section of the JPG file works, we've also included an optional `--jpg-sof2sos` flag, which reads the Start of Frame (SOF) marker until the SOS is found, and then reads an additional 45 bytes.  This is useful if the the stardard `--jpg-sos` is giving you false positives. 
5. In an effort to reduce false positives, we've added in the `--jpg-jump` flag which reads the compressed image data and creates a hex jump in the yara output if it finds repeated image bytes. This allows us to match on the SOF and SOS of the file, as well as some of the more unique data in the image.


### Contributing
Please contribute pull requests in python3, and submit any bugs you find as issues.
