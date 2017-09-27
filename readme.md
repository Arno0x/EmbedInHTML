Embed and hide any file in HTML
============

Author: Arno0x0x - [@Arno0x0x](http://twitter.com/Arno0x0x)

What this tool does is taking a file (*any type of file*), encrypt it, and embed it into an HTML file as ressource, along with an automatic download routine simulating a user clicking on the embedded ressource.

Then, when the user browses the HTML file, the embedded file is decrypted on the fly, saved in a temporary folder, and the file is then presented to the user as if it was being downloaded from the remote site. Depending on the user's browser and the file type presented, the file can be automatically opened by the browser.

This tool comes in two flavors, providing the same overall functionnality but with some slight changes in the way of using it:

  1. An **python script** which generates the output HTML file based on a template, using **RC4 encryption** routines, and embedding the decryption key within the output file. The resulting HTML can either be browsed by the targeted user or sent as an attachement.

  2. An **HTML/Javascript** that you can drag the file into be encrypted to, which generates the output HTML file, using the **WebCrypto API**, but NOT embedding the decryption material (*key and counter*). Instead, the decryption material is displayed as a set of URL parameters to be added into a URL pointing to the HTML resulting file: `http(s)://hosting.server.com/result.html#hexencodedkey!hexencodedcounter`. So the resulting HTML file cannot be sent as an attachment.
  The main advantage of this technique is that the decryption material is not embedded into the file itself, hence preventing analysis and even retrieval of the payload by any system which doesn't have the full URL (eg: intercepting proxy)

Side notes:
- This tool was inspired and derived from the great 'demiguise' tool : [https://github.com/nccgroup/demiguise](https://github.com/nccgroup/demiguise)

- The b64AndRC4 function used on the binary input (from the XLL file) is a mix of:
[https://gist.github.com/borismus/1032746](https://gist.github.com/borismus/1032746) and [https://gist.github.com/farhadi/2185197](https://gist.github.com/farhadi/2185197)

- Check [https://gist.github.com/Arno0x/f71a9db515ddea686ccdd77666bebbaa](https://gist.github.com/Arno0x/f71a9db515ddea686ccdd77666bebbaa) for an easy malicious XLL creation which is a perfect example of a malicious document one could try to deliver with this method.

- In the HTML template (*html.tpl file*) it is advised to insert your own key environmental derivation function below in place
of the 'keyFunction'. You should derive your key from the environment so that it only works on your intended target (*and not in a sandbox*).

Usage
----------------------

Few payload examples files are provided in the `payloads_examples` directory. For instance the `calc.xll` is an Excel add-in (XLL) file that contains a metasploit shellcode for x86 processes to launch the `calc.exe` process.

**Using the python script**

1/ Generate the malicious html file from the XLL file, along with a secret key:
`python embedInHTML.py -k mysecretkey -f example_calc.xll -o index.html`

2/ Expose the html file on a web server (*one can be optionnaly started for you with the `-w` flag*)

**Using the HTML/Javascript**

1/ Open the encryptFile.html file with a browser

2/ Simply drag the payload file into the page (*you can optionnaly change the output file name*)

3/ Save the resulting file and take note of the decryption material as URL parameters to be added to the file name


**Eventually...**

Point the target's browser to the html file and let the magic happen:

<img src="https://dl.dropboxusercontent.com/s/d53j2yev8itwu4e/deliverXLLviaHTML.jpg?dl=0" width="600">

DISCLAIMER
----------------
This tool is intended to be used in a legal and legitimate way only:
  - either on your own systems as a means of learning, of demonstrating what can be done and how, or testing your defense and detection mechanisms
  - on systems you've been officially and legitimately entitled to perform some security assessments (pentest, security audits)

Quoting Empire's authors:
*There is no way to build offensive tools useful to the legitimate infosec industry while simultaneously preventing malicious actors from abusing them.*