#BurpJDSer-ngng



A Burp Extender plugin, that will take deserialized java objects and encode them in XML using the [Xtream](http://xstream.codehaus.org/) library.

Why? This release fixes the bug in the other implementation in JDSer-ng which didn't actually allow modification of the request. Also extends it further, allowing proper use of the intruder/scanner modules for deserialized Java objects. 

Basically, it will deserialize, modify, reserialize, send on and (only in the case of the scanner) deserialize any responses that look like Java objects (to allow burp to flag any exception strings, etc.)

parts borrowed from [khai-tran](https://github.com/khai-tran/BurpJDSer) and IOActives extension https://github.com/IOActive/BurpJDSer-ng/

The IOActive guys wrote a far better readme than I could, so just use that:

##Usage

###1) Find and download client *.jar files
Few methods to locate the required jar files containing the classes we'll be deserializing.
* In case of a .jnlp file use [jnpdownloader](https://code.google.com/p/jnlpdownloader/)
* Locating jars in browser cache
* Looking for .jar in burp proxy history

Finally, create a "libs/" directory next to your burp.jar and put all the jars in it.

###2) Start Burp plugin
Download from [here](https://github.com/jonmurrayncc/JDSer-ngng/raw/master/Executables/BurpJDSer-ngng.jar) and simply load it in the Extender tab, the Output window will list all the loaded jars from ./libs/ 


###3) Inspect serialized Java traffic
Serialized Java content will automagically appear in the Deserialized Java input tab in appropriate locations (proxy history, interceptor, repeater, etc.)
Any changes made to the XML will serialize back once you switch to a different tab or send the request.

**Please note that if you mess up the XML schema or edit an object in a funny way, the re-serialization will fail and the error will be displayed in the input tab**

JARs reload when the extender is loaded. Everything is written to stdout (so run java -jar burpsuite.jar) and look for error messages/problems there.

cheers
