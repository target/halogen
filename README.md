# Halogen
Halogen is a tool to automate the creation of yara rules against image files embedded within a malicious document. 

![Halo Walkthrough](/images/halo_diagram.png)

## Halogen help 
```
python3 halogen.py -h
usage: halogen.py [-h] [-f FILE] [-d DIR] [-n NAME] [--png-idat] [--jpg-sos]

Halogen: Automatically create yara rules based on images embedded in office
documents.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File to parse
  -d DIR, --directory DIR
                        directory to scan for image files.
  -n NAME, --rule-name NAME
                        specify a custom name for the rule file
  --png-idat            For PNG matches, instead of starting with the PNG file
                        header, start with the IDAT chunk.
  --jpg-sos             For JPG matches, skip over the header and look for the
                        Start of Scan marker, and begin the match there.
```
## Testing it out
We've included some test document files with embedded images for you to test this out with.  Running `python3 halogen/halogen.py -d tests/ > /tmp/halogen_test.yara` will produce the test yara file containing all images found within the files inside the `tests/` directory.  
From here you can run `yara -s /tmp/halogen_test.yara tests/` and observe which images match which files. 

### Notes
1. We use two patterns for JPG matching.  One is less strict to the typical JPG file header, and we use this because we've seen some malicious files use this format.  If Halogen finds both, it'll default to writing out the more strict match.  Typically, these have the same matching content, so no detection really gets missed. 
2. For PNG files you can choose to start by default at the file header, or with `--png-idat` you can start at the IDAT chunk found within a PNG file.  We also reduced the bytes returned when matching on the IDAT chunk. 
3. Similar to the above, you can start JPG matches at the Start of Scan marker by using the `--jpg-sos` flag.   


### Contributing
Please contribute pull requests in python3, and submit any bugs you find as issues.
