Embed and hide any file in HTML
============

Author: Arno0x0x - [@Arno0x0x](http://twitter.com/Arno0x0x)

What this tool does is taking a file, encrypt it with a simple RC4 encryption stub, and embed it into an HTML file as ressource, along with an automatic download routine simulating a user clicking on the embeded ressource.

When the user browses to the HTML file, the embeded file is decrypted on the fly, saved in a temporary folder, and the file is then presented to the user as if it was being downloaded from the remote site. Depending on the user's browser and the file type presented, the file can be automatically opened by the browser.

Side notes:
- This tool was inspired and derived from the great 'demiguise' tool : [https://github.com/nccgroup/demiguise](https://github.com/nccgroup/demiguise)

- The b64AndRC4 function used on the binary input (from the XLL file) is a mix of:
[https://gist.github.com/borismus/1032746](https://gist.github.com/borismus/1032746) and [https://gist.github.com/farhadi/2185197](https://gist.github.com/farhadi/2185197)

- Check [https://gist.github.com/Arno0x/f71a9db515ddea686ccdd77666bebbaa](https://gist.github.com/Arno0x/f71a9db515ddea686ccdd77666bebbaa) for an easy malicious XLL creation

- In the HTML template (*html.tpl file*) it is advised to insert your own key environmental derivation function below in place
of the 'keyFunction'. You should derive your key from the environment so that it only works on your intended target (*and not in a sandbox*).

Usage
----------------------

Few examples files are provided in the `payloads_examples` directory. For instancethe `calc.xll` is an Excel add-in (XLL) file that contains a metasploit shellcode for x86 processes to launch the `calc.exe` process.

1/ Generate the malicious html file from the XLL file, along with a secret key:
`python embedInHTML.py -k mysecretkey -f example_calc.xll -o index.html`

2/ Expose the html file on a web server (*one can be optionnaly started for you with the `-w` flag*)

3/ Point your browser to the html file and let the magic happen:

<img src="https://dl.dropboxusercontent.com/s/d53j2yev8itwu4e/deliverXLLviaHTML.jpg?dl=0" width="600">

DISCLAIMER
----------------
This tool is intended to be used in a legal and legitimate way only:
  - either on your own systems as a means of learning, of demonstrating what can be done and how, or testing your defense and detection mechanisms
  - on systems you've been officially and legitimately entitled to perform some security assessments (pentest, security audits)

Quoting Empire's authors:
*There is no way to build offensive tools useful to the legitimate infosec industry while simultaneously preventing malicious actors from abusing them.*