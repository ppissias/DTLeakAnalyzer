# DtLeakAnalyzer

A tool for supporting identifying memory leaks with dtrace 

### Overview

This tool is intended to be used in supporting memory leak investigations with dtrace. 
dtrace (also known as dynamic tracing) is available for Solaris, FreeBSD, OSx and potentially other operating systems.

DtLeakAnalyzer consists of
- a **set of D scripts** (that attach to a process and start tracing)
- a **Java program that analyzes the traces** and produces a report 

Overall there are **4 basic modes of usage**:
- **Single memory allocator tracing session**, where we collect once traces for a process and analyze them 
- **Combination of multiple memory allocator tracing sessions**, where we combine multiple tracing sessions of different time lengths 
- **Combination of multiple short-term and long-term traces memory allocator** (There are different d-scripts for the short-term and long-term traces. The short-term traces are used to train the system in order to interpret the long term traces)
- **Process memory growth analysis** 

In summary it provides the following features 
- **Single memory allocator tracing session**  
-- presentation of call stacks that appear to be causing memory leaks 
-- heuristic analysis for pointing out strongly suspected memory leaks 
-- presentation of call stacks that appear to be freeing memory wrongly 
-- heuristic analysis for pointing out stringly suspected wrong free call stacks 
-- identification of double free operations
-- presentation of a combined call stack where the potential memory leaks are identified
- **Combination of multiple memory allocator tracing sessions** (on top of the features above)
-- combined presentation of the occurence of suspected call stacks for all trace files
-- heuristic analysis for pointing out very strongly suspected call stacks
- **Combination of multiple short-term and long-term traces** (on top of the features above)
-- heuristic analysis of long term traces
- **Process memory growth analysis**
-- presentation of call stacks that caused memory growth, including occurences and total size
-- presentation of a combined call stack where all calls that caused memory growth are presented 

More information on the usage and capabilities of DtLeakAnalyzer can be found [in the DtLeakAnalyzer usage manual](resources/DtLeakAnalyzer.pdf)

### Running

Detailed instructions can be found in [in the DtLeakAnalyzer usage manual](resources/DtLeakAnalyzer.pdf)

As a **single memory allocator tracing session** example, first we collect traces from the running process
i.e. 
``` 
> ./trace-memalloc.d 14291 > trace-memalloc.log 
``` 
(press ctrl^C when we are done) 

then we tun the trace analysis program 
``` 
> java -jar dtleakanalyzer.jar -f memalloc trace-memalloc.log trace-memalloc.log.report 
``` 
The output of the trace analysis tool for this case is:
``` 
Started memory allocator analysis for file memalloc trace-memalloc.log on:Thu Nov 08 08:03:54 CET 2018
Finished memory allocator analysis for file memalloc trace-memalloc.log on:Thu Nov 08 08:04:05 CET 2018
Call statistics
Found 142511 malloc calls
Found 0 calloc calls
Found 0 realloc calls
Found 142427 free calls

Double free issues
Found 0 double free stacks in total

Free non-allocated memory issues (may also be potential memory leaks)
Found 2617 stacks that freed memory that was not allocated during the period of the trace
Found 17 unique stacks that freed memory that was not allocated during the period of the trace
Found 495 unique stacks that correctly freed memory
Found 0 unique stacks that have never been found to correctly free memory

Memory leak issues
Found 2701 potential memory leaks in total
Found 44 unique potential memory leak stacks (suspects)
Found 553 unique stacks that allocated memory that was correctly freed
Found 1 unique stacks that were never correctly deleted/freed (strong suspects)

``` 
The report will be procuded in the specified file: trace-memalloc.log.report and will contain all relevant information about the identified call stacks and heuristics. 

### Compiling

The D scripts do not need any compilation. 

Compiling the java source code to produce the trace analysis executable:

Extract the reporitory and run the compile.bat or .sh 

```

c:\dev\projects\DTLeakAnalyzer>compile.bat

c:\dev\projects\DTLeakAnalyzer>javac -d classes src/DTLeakAnalyzer.java

c:\dev\projects\DTLeakAnalyzer>jar cvfm dtleakanalyzer.jar resources/manifest.txt -C classes .
added manifest
adding: classes.txt(in = 0) (out= 0)(stored 0%)
adding: DTLeakAnalyzer$1.class(in = 561) (out= 380)(deflated 32%)
adding: DTLeakAnalyzer$10.class(in = 1475) (out= 709)(deflated 51%)
adding: DTLeakAnalyzer$11.class(in = 795) (out= 458)(deflated 42%)
adding: DTLeakAnalyzer$12.class(in = 799) (out= 461)(deflated 42%)
adding: DTLeakAnalyzer$13.class(in = 806) (out= 467)(deflated 42%)
adding: DTLeakAnalyzer$14.class(in = 1991) (out= 872)(deflated 56%)
adding: DTLeakAnalyzer$2.class(in = 561) (out= 380)(deflated 32%)
adding: DTLeakAnalyzer$3.class(in = 561) (out= 376)(deflated 32%)
adding: DTLeakAnalyzer$4.class(in = 838) (out= 458)(deflated 45%)
adding: DTLeakAnalyzer$5.class(in = 838) (out= 463)(deflated 44%)
adding: DTLeakAnalyzer$6.class(in = 838) (out= 459)(deflated 45%)
adding: DTLeakAnalyzer$7.class(in = 842) (out= 456)(deflated 45%)
adding: DTLeakAnalyzer$8.class(in = 806) (out= 463)(deflated 42%)
adding: DTLeakAnalyzer$9.class(in = 806) (out= 464)(deflated 42%)
adding: DTLeakAnalyzer$BrkStackOccurence.class(in = 1024) (out= 568)(deflated 44%)
adding: DTLeakAnalyzer$BrkTraceEntry.class(in = 3561) (out= 1856)(deflated 47%)
adding: DTLeakAnalyzer$BrkTraceEntryType.class(in = 990) (out= 523)(deflated 47%)
adding: DTLeakAnalyzer$DTGenericLeakLogEntry.class(in = 3648) (out= 1850)(deflated 49%)
adding: DTLeakAnalyzer$DTLeakAnalyzerFileType.class(in = 1029) (out= 519)(deflated 49%)
adding: DTLeakAnalyzer$DTLeakBrkLogEntry.class(in = 3586) (out= 1841)(deflated 48%)
adding: DTLeakAnalyzer$DTLeakBrkReportEntry.class(in = 998) (out= 548)(deflated 45%)
adding: DTLeakAnalyzer$DTLeakCppLogEntry.class(in = 3531) (out= 1830)(deflated 48%)
adding: DTLeakAnalyzer$DTLeakGenLogEntry.class(in = 3640) (out= 1873)(deflated 48%)
adding: DTLeakAnalyzer$DTLeakLogBrkEntryType.class(in = 1018) (out= 521)(deflated 48%)
adding: DTLeakAnalyzer$DTLeakLogCppEntryType.class(in = 1133) (out= 586)(deflated 48%)
adding: DTLeakAnalyzer$DTLeakLogEntry.class(in = 3510) (out= 1828)(deflated 47%)
adding: DTLeakAnalyzer$DTLeakLogEntryType.class(in = 1112) (out= 586)(deflated 47%)
adding: DTLeakAnalyzer$DTLeakLogGenEntryType.class(in = 1128) (out= 580)(deflated 48%)
adding: DTLeakAnalyzer$DTLeakMemAllocLogEntry.class(in = 3649) (out= 1866)(deflated 48%)
adding: DTLeakAnalyzer$DTLeakReportEntry.class(in = 799) (out= 454)(deflated 43%)
adding: DTLeakAnalyzer$DTLeakWrongDeleteEntry.class(in = 824) (out= 414)(deflated 49%)
adding: DTLeakAnalyzer$DTLeakWrongDeleteReportEntry.class(in = 1020) (out= 510)(deflated 50%)
adding: DTLeakAnalyzer$MemoryAllocationTraceEntryType.class(in = 1191) (out= 596)(deflated 49%)
adding: DTLeakAnalyzer$MemoryAllocatorTraceEntry.class(in = 3697) (out= 1873)(deflated 49%)
adding: DTLeakAnalyzer$StackOccurence.class(in = 1142) (out= 583)(deflated 48%)
adding: DTLeakAnalyzer$TraceFileType.class(in = 966) (out= 521)(deflated 46%)
adding: DTLeakAnalyzer.class(in = 36673) (out= 15321)(deflated 58%)

```
This will create the dtleakanalyzer.jar executable jar on the current folder. 

## Contributing

 
Please feel free to extend the project!


## License

  

This project is licensed under the MIT License (https://opensource.org/licenses/MIT)
- see the [LICENSE](LICENSE) file for details


  

## Acknowledgments

  
* Thanks to Brendan Gregg for his excellent page on memory leaks and ways to identify them: http://www.brendangregg.com/Solaris/memoryflamegraphs.html
* Thanks to the authors of this article on how to use dtrace for supporting memory leak investigations : https://blogs.oracle.com/openomics/investigating-memory-leaks-with-dtrace 
 