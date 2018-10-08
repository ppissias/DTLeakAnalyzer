# Dtleakanalyzer

A tool for supporting identifying memory leaks with dtrace 

### Overview

This tool is intended to be used in supporting memory leak investigations with dtrace. It consists of
- a set of D scripts (that attach to a process and start tracing)
- a Java program that analyzes the traces and produces a report 

It re-uses the .d script defined in https://blogs.oracle.com/openomics/investigating-memory-leaks-with-dtrace moving most of the trace analysis to the newly created Java post-processing program. Moreover it tries to detect wrong delete operations (i.e. delete on memory that was allocated with new[])

### Running

First we collect traces from the running process
i.e. 
``` 
> trace_new_delete.d <PID> > traces.txt 
``` 
(press ctrl^C when we are done) 
then we demangle names in the call stack (this is an optional step to show the call stacks of your program clearly) 
``` 
> c++filt traces.txt > traces.dem.txt 
``` 
then we tun the trace analysis program 
``` 
> java -jar dtleakanalyzer.jar traces.dem.txt traces.dem.txt.report 
Output: 
Trace analyser started on Mon Oct 08 13:40:45 CEST 2018


Processing wrong deletes [delete on memory that was allocated with new[]), found 0 instances
found 0 unique wrong delete stacks
Analyzing 2290 potential memory leaks
Processing completed.
Detected 108 potential memory leaks

finished on Mon Oct 08 13:40:47 CEST 2018
``` 
This will produce a report (traces.dem.txt.report) which contains all useful information and potential memory leaks.


### Compiling

The D scripts do not need any compilation. 

Compiling the java source code to produce the trace analysis executable:

Extract the reporitory and run the compile.bat or .sh 

```

c:\dev\projects\DTLeakAnalyzer>javac -d classes src/DTLeakAnalyzer.java

c:\dev\projects\DTLeakAnalyzer>jar cvfm dtleakanalyzer.jar resources/manifest.txt -C classes .
added manifest
adding: DTLeakAnalyzer$1.class(in = 894) (out= 465)(deflated 47%)
adding: DTLeakAnalyzer$2.class(in = 839) (out= 451)(deflated 46%)
adding: DTLeakAnalyzer$3.class(in = 793) (out= 479)(deflated 39%)
adding: DTLeakAnalyzer$DTLeakLogEntry.class(in = 3509) (out= 1811)(deflated 48%)
adding: DTLeakAnalyzer$DTLeakLogEntryType.class(in = 1112) (out= 582)(deflated 47%)
adding: DTLeakAnalyzer$DTLeakReportEntry.class(in = 703) (out= 431)(deflated 38%)
adding: DTLeakAnalyzer$DTLeakWrongDeleteEntry.class(in = 806) (out= 412)(deflated 48%)
adding: DTLeakAnalyzer$DTLeakWrongDeleteReportEntry.class(in = 1020) (out= 506)(deflated 50%)
adding: DTLeakAnalyzer.class(in = 7823) (out= 3849)(deflated 50%)

```
This will create the dtleakanalyzer.jar on the current folder. 

## Contributing

  

Please feel free to extend the project!

  

## License

  

This project is licensed under the MIT License (https://opensource.org/licenses/MIT)
- see the [LICENSE](LICENSE) file for details


  

## Acknowledgments

  

* Thanks to the authors of the original article on how to use dtrace for supporting memory leak investigations : https://blogs.oracle.com/openomics/investigating-memory-leaks-with-dtrace moving
 