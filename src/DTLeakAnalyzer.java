import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.LogManager;


/**
 * Tool for analyzing logs produced with dtrace (under Solaris and other platforms that support dtrace) in support of 
 * memory leak investigations.
 * 
 * The processing logic is written as a single class file intentionally, as to 
 * try and provide a single "processing script" of the trace files. 
 * However the processing complexity has risen and it might be necessary to split the logic
 * in multiple files if further processing logic is to be added. 
 * 
 * @author Petros Pissias
 *
 */
public class DTLeakAnalyzer {
	//this file contains the traces
	private final String inFile; 
	
	//this file will contain the analysis of the traces
	private final String outFile;
	
	//start / end trace sequences
	private static final String entryStartCharSequence = "<__";
	private static final String entryEndCharSequence = "__>";
	
	//the log file output writer
	private final PrintWriter writer;
		
	//used for memory allocator analysis
	private final List<StackOccurence> uniquePotentialLeakStacks;
	private final List<StackOccurence> uniquePotentialLeakStacksNeverFreed; //more confident potential leaks
	private final List<StackOccurence> uniquePotentialWrongFreeStacks;
	private final List<StackOccurence> uniquePotentialWrongFreeStacksNeverCorrectlyFreed; //more confident wrong free/deletes
	private int totalPoteltialLeakSuspects;
	private int totalPotentialWrongFreeSuspects;
	//counters
	private int totalMallocCalls = 0;
	private int totalCallocCalls = 0;
	private int totalReallocCalls = 0;
	private int totalFreeCalls = 0;
	
	//combined potential leak stack
	private String combinedLeakStackSuspects = ""; 
	private String combinedLeakStackStrongSuspects = ""; 
	
	//store information for combined file processing
	private final List<MemoryAllocatorTraceEntry> uniqueSuccessfulFreeStacks; //store unique stacks that correctly freed memory
	private final List<MemoryAllocatorTraceEntry> uniqueSuccessfullyDeletedStacks; //store unique stacks that allocated memory that was correctly freed
	
	//used for memory allocator analysis to detect double free operations
	private final List<StackOccurence> uniqueDoubleFreeStacks; 
	private int totalDoubleFreeStacks;

	//used for brk processing
	private final List<BrkStackOccurence> uniqueBrkStacks; //all brk stacks along with their appearance frequency and size
	private final List<BrkStackOccurence> uniqueFailedBrkStacks;
	private int totalBrkIncreaseStacks;
	private int totalBrkDecreaseStacks;
	private int totalBrkNeutralStacks;
	private int totalBrkFailedStacks;
	
	//combined brk stack
	private String combinedBrkStacks; 
		
	//used for processed files analysis
	private final List<StackOccurence> uniqueAllocationStacks;
	private final List<StackOccurence> uniqueDeallocationStacks;
	private final List<StackOccurence> uniqueUnfreedAllocationStacks;
	private final List<StackOccurence> uniqueUnknownDeallocationStacks;
	
	public static void printArgs(){
		System.out.println("arguments: -f <type> <input file> <output file>" );;
		System.out.println("arguments: -d <directory> <output file>" );
		System.out.println("arguments: -p <directory> -d <directory> <output file>" );
		System.out.println("<type> = memalloc or brk.\nExample: <prog> -f memalloc inputFile outputFile"); 	
	}
	
	/**
	 * Entry point to start the analysis tool
	 * @param args arguments: <input file> <output file>
	 */
	public static void main(String[] args) throws IOException{

		if (args.length < 3 || args.length > 5) {
			printArgs();
			return;
		}

		if (args.length == 4) {	
			if (args[1].equals("memalloc")) {
				//single file mode, generic 
				DTLeakAnalyzer dtLeakAnalyzer = new DTLeakAnalyzer(args[2], args[3]);
				DTLeakAnalyzer.logMessage("Started memory allocator analysis for file "+args[2]+" on:"+new Date(), true, dtLeakAnalyzer.writer);
				dtLeakAnalyzer.performMemoyAllocatorAnalysis();
				DTLeakAnalyzer.logMessage("Finished memory allocator analysis for file "+args[2]+" on:"+new Date(), true, dtLeakAnalyzer.writer);			
				dtLeakAnalyzer.printAnalysisInformation(TraceFileType.MEMALLOC);
			} else if (args[1].equals("brk")) {
				//single file mode, generic 
				DTLeakAnalyzer dtLeakAnalyzer = new DTLeakAnalyzer(args[2], args[3]);
				DTLeakAnalyzer.logMessage("Started process memory increase analysis for file "+args[2]+" on:"+new Date(), true, dtLeakAnalyzer.writer);
				dtLeakAnalyzer.performBrkAnalysis();
				DTLeakAnalyzer.logMessage("Finished process memory increase analysis for file "+args[2]+" on:"+new Date(), true, dtLeakAnalyzer.writer);			
				dtLeakAnalyzer.printAnalysisInformation(TraceFileType.BRK);
			}else {
				printArgs();
				return;
			}		
		}else if (args.length == 3) {
			if (args[0].equals("-d")) {
				//directory mode , memory allocator analysis
				
				File[] files = new File(args[1]).listFiles(new FilenameFilter() {

					@Override
					public boolean accept(File dir, String name) {
						if (name.endsWith(".report")) {
							return false;	
						} else {
							return true;
						}						
					}
					
				});
				Arrays.sort(files);
	
				//get each input file and do an analysis. Then write the combined results
				Map<File, DTLeakAnalyzer> fileAnalysisResults = new HashMap<File, DTLeakAnalyzer>();
				for(File resultsFile : files) {
					DTLeakAnalyzer dtLeakAnalyzer = new DTLeakAnalyzer(resultsFile.getAbsolutePath(), resultsFile.getAbsolutePath()+".report");
					DTLeakAnalyzer.logMessage("Started memory allocator analysis for file "+resultsFile+" on:"+new Date(), true, dtLeakAnalyzer.writer);
					dtLeakAnalyzer.performMemoyAllocatorAnalysis();
					DTLeakAnalyzer.logMessage("Finished memory allocator analysis for file "+resultsFile+" on:"+new Date(), true, dtLeakAnalyzer.writer);
					dtLeakAnalyzer.printAnalysisInformation(TraceFileType.MEMALLOC);
					fileAnalysisResults.put(resultsFile, dtLeakAnalyzer);
				}
	
				//now write the combined results
				printMemoryAllocatorCombinedAnalysisResults(fileAnalysisResults, args[2]);		
								
			} else {
				printArgs();
				return;				
			}
		} else if (args.length == 5 || args.length == 6) {
			if (args[0].equals("-p") && args[2].equals("-d")) {
				//directory mode for already "dtrace-processed" files 
				//in this mode, we process all the memory allocator trace files and gather information
				//that is used in providing heuristics.
				File[] memallocFiles = new File(args[3]).listFiles(new FilenameFilter() {
					
					@Override
					public boolean accept(File dir, String name) {
						if (name.endsWith(".report")) {
							return false;	
						} else {
							return true;
						}						
					}
					
				});
				Arrays.sort(memallocFiles);
				
				//get the relationship information
				Map<StackOccurence, List<StackOccurence>>  stackRelationships = getFreeMemoryStackRelationships(memallocFiles);
								
				//process processed files
				
				File[] processedfiles = new File(args[1]).listFiles(new FilenameFilter() {
	
					@Override
					public boolean accept(File dir, String name) {
						if (name.endsWith(".report")) {
							return false;	
						} else {
							return true;
						}						
					}
					
				});
				Arrays.sort(processedfiles);
	
				//get each input file and do an analysis. Then write the combined results
				Map<File, DTLeakAnalyzer> fileAnalysisResults = new HashMap<File, DTLeakAnalyzer>();
				for(File resultsFile : processedfiles) {
					DTLeakAnalyzer dtLeakAnalyzer = new DTLeakAnalyzer(resultsFile.getAbsolutePath(), resultsFile.getAbsolutePath()+".report");
					DTLeakAnalyzer.logMessage("Started processing file "+resultsFile+" on:"+new Date(), true, dtLeakAnalyzer.writer);
					dtLeakAnalyzer.performProcessedFileAnalysis(stackRelationships);
					DTLeakAnalyzer.logMessage("Finished processing file "+resultsFile+" on:"+new Date(), true, dtLeakAnalyzer.writer);
					int numAlloc = 0; 
					int numDealloc=0;
					for (StackOccurence rep :dtLeakAnalyzer.uniqueAllocationStacks) {
						numAlloc += rep.timesFound;
					}
					for (StackOccurence rep :dtLeakAnalyzer.uniqueDeallocationStacks) {
						numDealloc += rep.timesFound;
					}
					DTLeakAnalyzer.logMessage("Found "+numAlloc+" memory allocation calls", true, dtLeakAnalyzer.writer);
					DTLeakAnalyzer.logMessage("Found "+dtLeakAnalyzer.uniqueAllocationStacks.size()+" unique memory allocation stacks", true, dtLeakAnalyzer.writer);
					DTLeakAnalyzer.logMessage("Found "+numDealloc+" memory de-allocation calls", true, dtLeakAnalyzer.writer);					
					DTLeakAnalyzer.logMessage("Found "+dtLeakAnalyzer.uniqueDeallocationStacks.size()+" unique memory de-allocation stacks", true, dtLeakAnalyzer.writer);

					int numAllocUnfreed = 0;
					int numDeallocUnknown = 0;
					for (StackOccurence rep :dtLeakAnalyzer.uniqueUnfreedAllocationStacks) {
						numAllocUnfreed += rep.timesFound;
					}
					for (StackOccurence rep :dtLeakAnalyzer.uniqueUnknownDeallocationStacks) {
						numDeallocUnknown += rep.timesFound;
					}
					DTLeakAnalyzer.logMessage("Found "+numAllocUnfreed+" (unfreed) memory allocation calls from "+dtLeakAnalyzer.uniqueUnfreedAllocationStacks.size()+" unique allocation stacks (suspect memory leaks)", true, dtLeakAnalyzer.writer);
					DTLeakAnalyzer.logMessage("Found "+numDeallocUnknown+" unknown free calls from "+dtLeakAnalyzer.uniqueUnknownDeallocationStacks.size()+" unique free stacks", true, dtLeakAnalyzer.writer);
					
					DTLeakAnalyzer.logMessage("number of memory allocation calls - number of free calls = "+(numAlloc-numDealloc)+"\n", true, dtLeakAnalyzer.writer);
					fileAnalysisResults.put(resultsFile, dtLeakAnalyzer);
					dtLeakAnalyzer.writer.close();
				}
	
				//now write the combined results
				boolean printNormalStacks = false;
				if (args.length == 6) {
					printNormalStacks = true;
				}
				printProcessedFilesCombinedAnalysisResults(fileAnalysisResults, args[4], printNormalStacks);
			}else {
				printArgs();
				return;				
			}			
		}
	}
	
	/**
	 * new instance of the analyzer 
	 * @param inFile the traces
	 * @param outFile the output analysis of the traces that will be produced 
	 * @throws UnsupportedEncodingException 
	 * @throws FileNotFoundException 
	 * @throws Exception in case the traces cannot be parsed or the files cannot be accessed
	 */
	public DTLeakAnalyzer(String inFile, String outFile) throws FileNotFoundException, UnsupportedEncodingException {
		this.inFile = inFile;
		this.outFile = outFile;
		
		uniquePotentialLeakStacks = new ArrayList<StackOccurence>();
		uniquePotentialLeakStacksNeverFreed = new ArrayList<StackOccurence>();
		uniquePotentialWrongFreeStacks = new ArrayList<StackOccurence>();
		uniqueDoubleFreeStacks = new ArrayList<StackOccurence>();
		uniquePotentialWrongFreeStacksNeverCorrectlyFreed = new ArrayList<StackOccurence>();
		uniqueBrkStacks = new ArrayList<BrkStackOccurence>();
		uniqueFailedBrkStacks = new ArrayList<BrkStackOccurence>();
		
		//store some for combined operations
		uniqueSuccessfulFreeStacks = new ArrayList<MemoryAllocatorTraceEntry>();
		uniqueSuccessfullyDeletedStacks = new ArrayList<MemoryAllocatorTraceEntry>();
		
		//for dtrace-processed files
		uniqueAllocationStacks = new ArrayList<StackOccurence>();
		uniqueDeallocationStacks = new ArrayList<StackOccurence>();
		uniqueUnfreedAllocationStacks = new ArrayList<StackOccurence>(); 
		uniqueUnknownDeallocationStacks = new ArrayList<StackOccurence>(); ;
		
		//open output file
		if (outFile == null) {
			writer = null;
		} else {
			writer = new PrintWriter(outFile, "UTF-8");
		}
	}
	

	/**
	 * Returns the relationships between stacks that free memory and stacks that allocated memory
	 * More specifically, it links each stack that freed memory, with the stack(s) that had allocated the memory
	 * @param memallocFiles the memory allocator trace files
	 * @return the relationship map
	 * @throws IOException 
	 */
	public static Map<StackOccurence, List<StackOccurence>> getFreeMemoryStackRelationships(File[] memallocFiles) throws IOException {		
		Map<StackOccurence, List<StackOccurence>> stackRelationshipMap = new HashMap<StackOccurence, List<StackOccurence>>();
		
		System.out.println("Collecting memory allocator stack relationships");
		for(File resultsFile : memallocFiles) {
			System.out.println("processing file:"+resultsFile.getAbsolutePath());
			//map to keep track of memory allocations
			Map<String, MemoryAllocatorTraceEntry> memoryAllocation = new HashMap<String, MemoryAllocatorTraceEntry>();
			
			//open the traces file
			try (BufferedReader br = new BufferedReader(new FileReader(resultsFile.getAbsolutePath()))) {
				
				//read all entries
				MemoryAllocatorTraceEntry traceEntry = null;			
				while ((traceEntry = readMemoryAllocatorTraceEntry(br)) != null) {
					//now process the entry
					if (traceEntry.getType().equals(MemoryAllocationTraceEntryType.MALLOC)) {
						//sanity check
						if (memoryAllocation.containsKey(traceEntry.getAddress())) {
							//this should not happen.
							throw new IOException("Found allocation on memory address:"+traceEntry.getAddress()+" that was already allocated by: "+memoryAllocation.get(traceEntry.getAddress()));
						}
						
						//add to map
						memoryAllocation.put(traceEntry.getAddress(), traceEntry);
											
					} else if (traceEntry.getType().equals(MemoryAllocationTraceEntryType.CALLOC)) {
						//sanity check
						if (memoryAllocation.containsKey(traceEntry.getAddress())) {
							//this should not happen.
							throw new IOException("Found allocation on memory address:"+traceEntry.getAddress()+" that was already allocated by: "+memoryAllocation.get(traceEntry.getAddress()));
						}
						
						//add to map
						memoryAllocation.put(traceEntry.getAddress(), traceEntry);
												
					} else if (traceEntry.getType().equals(MemoryAllocationTraceEntryType.REALLOC)) {
						//sanity check
						if (traceEntry.getAddress().equals(traceEntry.getPreviousAddress())) {
							//the realloc did not move the memory address, no need to do something

							//add to map, updating the previous entry if it exists
							memoryAllocation.put(traceEntry.getAddress(), traceEntry);						
						} else {
							//new address, the realloc moved the memory
							if (memoryAllocation.containsKey(traceEntry.getAddress())) {
								//this should not happen.
								throw new IOException("Found allocation on memory address:"+traceEntry.getAddress()+" that was already allocated by: "+memoryAllocation.get(traceEntry.getAddress()));
							}

							//add the new address of the allocation
							memoryAllocation.put(traceEntry.getAddress(), traceEntry);		

							//remove previous allocation
							MemoryAllocatorTraceEntry removed = memoryAllocation.remove(traceEntry.getPreviousAddress());
							
							//add the previous deallocation to the relationships
							//keep a reference of this successful delete stack
							/**
							 * We are doing this special handling here for realloc, because on the .proc d-script
							 * we treat realloc calls as an allocation and a de-allocation. 
							 * So we must associate the relevant stack as being deleted by this deallocation.
							 */
							boolean found = false;
							OUTTER_LOOP:
							for (StackOccurence existingSuccesfulFree : stackRelationshipMap.keySet()) {
								if (existingSuccesfulFree.getStack().equals(traceEntry.getCallStack())) {								
									found = true;
									existingSuccesfulFree.increaseTimesFound();
									//add this stack if it does not exist
									List<StackOccurence> relatedAllocationStacks = stackRelationshipMap.get(existingSuccesfulFree);
									boolean foundRelatedStack = false;
									INNER_LOOP:
									for (StackOccurence relatedStackOccurence : relatedAllocationStacks) {
										//check if the freed memory was from a stack that we already know
										if (relatedStackOccurence.getStack().equals(removed.getCallStack())) {
											foundRelatedStack = true;
											relatedStackOccurence.increaseTimesFound();
											break INNER_LOOP;
										}
									}
									if (!foundRelatedStack) { //related stack not found
										relatedAllocationStacks.add(new StackOccurence(removed.getCallStack()));
									}
									break OUTTER_LOOP;
								}
							}
							if (!found) { //free stack not found
								//create a list and add the stack that its memory allocation was successfully freed
								List<StackOccurence> allocationStacks = new ArrayList<StackOccurence>();
								allocationStacks.add(new StackOccurence(removed.getCallStack()));
								//add the free stack along with the list
								stackRelationshipMap.put(new StackOccurence(traceEntry.getCallStack()), allocationStacks);
							}							
							
						}
											
					}else if (traceEntry.getType().equals(MemoryAllocationTraceEntryType.FREE)) {
						//check if it exists already on the map
						if (memoryAllocation.containsKey(traceEntry.getAddress())) {
							//as expected, we had an allocation and this is the de-allocation
							MemoryAllocatorTraceEntry removed = memoryAllocation.remove(traceEntry.getAddress());
							
							//keep a reference of this successful delete stack
							boolean found = false;
							OUTTER_LOOP:
							for (StackOccurence existingSuccesfulFree : stackRelationshipMap.keySet()) {
								if (existingSuccesfulFree.getStack().equals(traceEntry.getCallStack())) {								
									found = true;
									existingSuccesfulFree.increaseTimesFound();
									//add this stack if it does not exist
									List<StackOccurence> relatedAllocationStacks = stackRelationshipMap.get(existingSuccesfulFree);
									boolean foundRelatedStack = false;
									INNER_LOOP:
									for (StackOccurence relatedStackOccurence : relatedAllocationStacks) {
										//check if the freed memory was from a stack that we already know
										if (relatedStackOccurence.getStack().equals(removed.getCallStack())) {
											foundRelatedStack = true;
											relatedStackOccurence.increaseTimesFound();
											break INNER_LOOP;
										}
									}
									if (!foundRelatedStack) { //related stack not found
										relatedAllocationStacks.add(new StackOccurence(removed.getCallStack()));
									}
									break OUTTER_LOOP;
								}
							}
							if (!found) { //free stack not found
								//create a list and add the stack that its memory allocation was successfully freed
								List<StackOccurence> allocationStacks = new ArrayList<StackOccurence>();
								allocationStacks.add(new StackOccurence(removed.getCallStack()));
								//add the free stack along with the list
								stackRelationshipMap.put(new StackOccurence(traceEntry.getCallStack()), allocationStacks);
							}			
							
							
						} else {
							//not expected, but can happen since we are not monitoring all allocations from the beginning of the execution
							
						}

					} else {
						throw new IOException("Cannot handle entry type:"+traceEntry.getType());
					}					
				}
			}catch (IOException e) {
				System.out.println("problem reading input (traces) file:"+e.getMessage());
				
				throw e;
			} 			
		}
		
		int valuesCount = 0;
		for (List<StackOccurence> values : stackRelationshipMap.values()) {
			valuesCount += values.size();
		}
		System.out.println("found in total "+stackRelationshipMap.size()+" unique free stacks, that freed memory allocated from "+valuesCount+" stacks\n");
		return stackRelationshipMap;
	}

	
	/**
	 * Performs the traces analysis for a generic program (using free/malloc/realloc/calloc)
	 * @throws IOException 
	 */
	public void performMemoyAllocatorAnalysis() throws IOException {				
		//map to keep track of memory allocations
		Map<String, MemoryAllocatorTraceEntry> memoryAllocation = new HashMap<String, MemoryAllocatorTraceEntry>();

		//list to keep track of free operations to unallocated memory
		List<MemoryAllocatorTraceEntry> freeUnallocagedMemoryStacks = new ArrayList<MemoryAllocatorTraceEntry>();

		//map to keep track of memory de-allocations related to free operations, for detecting double free operations
		Map<String, MemoryAllocatorTraceEntry> freedAndNotReusedMemory = new HashMap<String, MemoryAllocatorTraceEntry>();
		
		//list to keep track of double free stacks (errors)
		List<MemoryAllocatorTraceEntry> doubleFree = new ArrayList<MemoryAllocatorTraceEntry>();
		
		//open the traces file
		try (BufferedReader br = new BufferedReader(new FileReader(inFile))) {
			
			//read all entries
			MemoryAllocatorTraceEntry traceEntry = null;			
			while ((traceEntry = readMemoryAllocatorTraceEntry(br)) != null) {

				//now process the entry
				if (traceEntry.getType().equals(MemoryAllocationTraceEntryType.MALLOC)) {
					totalMallocCalls++;
					//sanity check
					if (memoryAllocation.containsKey(traceEntry.getAddress())) {
						//this should not happen.
						throw new IOException("Entry:"+traceEntry+"\nFound allocation on memory address:"+traceEntry.getAddress()+" that was already allocated by: "+memoryAllocation.get(traceEntry.getAddress()));
					}
					
					//add to map
					memoryAllocation.put(traceEntry.getAddress(), traceEntry);
					
					if (freedAndNotReusedMemory.containsKey(traceEntry.getAddress())) {
						//System.out.println("removing from memoryFree list:"+traceEntry.getAddress());
						//we now re-use memory that was freed, remove the address from the map
						freedAndNotReusedMemory.remove(traceEntry.getAddress());
					}
					
				} else if (traceEntry.getType().equals(MemoryAllocationTraceEntryType.CALLOC)) {
					totalCallocCalls++;
					//sanity check
					if (memoryAllocation.containsKey(traceEntry.getAddress())) {
						//this should not happen.
						throw new IOException("Entry:"+traceEntry+"\nFound allocation on memory address:"+traceEntry.getAddress()+" that was already allocated by: "+memoryAllocation.get(traceEntry.getAddress()));
					}
					
					//add to map
					memoryAllocation.put(traceEntry.getAddress(), traceEntry);
					
					if (freedAndNotReusedMemory.containsKey(traceEntry.getAddress())) {
						//System.out.println("removing from memoryFree list:"+traceEntry.getAddress());
						//we now re-use memory that was freed, remove the address from the map
						freedAndNotReusedMemory.remove(traceEntry.getAddress());
					}
					
				} else if (traceEntry.getType().equals(MemoryAllocationTraceEntryType.REALLOC)) {
					totalReallocCalls++;
					//sanity check
					if (traceEntry.getAddress().equals(traceEntry.getPreviousAddress())) {
						//the realloc did not move the memory address, no need to do something

						//add to map, updating the previous entry if it exists
						memoryAllocation.put(traceEntry.getAddress(), traceEntry);						
					} else {
						//new address, the realloc moved the memory
						if (memoryAllocation.containsKey(traceEntry.getAddress())) {
							//this should not happen.
							throw new IOException("Entry:"+traceEntry+"\nFound allocation on memory address:"+traceEntry.getAddress()+" that was already allocated by: "+memoryAllocation.get(traceEntry.getAddress()));
						}

						//remove previous allocation
						memoryAllocation.remove(traceEntry.getPreviousAddress());						
						//add the new address of the allocation
						memoryAllocation.put(traceEntry.getAddress(), traceEntry);						
					}
					
					if (freedAndNotReusedMemory.containsKey(traceEntry.getAddress())) {
						//System.out.println("removing from memoryFree list:"+traceEntry.getAddress());
						//we now re-use memory that was freed, remove the address from the map
						freedAndNotReusedMemory.remove(traceEntry.getAddress());
					}
					
				}else if (traceEntry.getType().equals(MemoryAllocationTraceEntryType.FREE)) {
					totalFreeCalls++;
					//check if it exists already on the map
					if (memoryAllocation.containsKey(traceEntry.getAddress())) {
						//as expected, we had an allocation and this is the de-allocation
						MemoryAllocatorTraceEntry removed = memoryAllocation.remove(traceEntry.getAddress());
						
						//keep a reference of this successful delete stack
						boolean found = false;
						for (MemoryAllocatorTraceEntry existingSuccesfulDelete : uniqueSuccessfulFreeStacks) {
							if (existingSuccesfulDelete.getCallStack().equals(traceEntry.getCallStack())) {								
								found = true;
								break;
							}
						}
						if (!found) {
							uniqueSuccessfulFreeStacks.add(traceEntry);
						}			
						
						//keep a reference of the successfully deleted stack
						boolean foundRemoved = false;
						for (MemoryAllocatorTraceEntry existingSuccesfullyDeleted : uniqueSuccessfullyDeletedStacks) {
							if (existingSuccesfullyDeleted.getCallStack().equals(removed.getCallStack())) {
								foundRemoved = true;
								break;
							}
						}
						
						if (!foundRemoved) {
							uniqueSuccessfullyDeletedStacks.add(removed);
						}
						
						//add to the map to keep track for double free operations
						if (freedAndNotReusedMemory.containsKey(traceEntry.getAddress())) {
							//this is an error
							throw new IOException("Entry:"+traceEntry+"\nFound free on memory address:"+traceEntry.getAddress()+" that was succesfully removed from the memory allocation map, but appears also on the freed and not reused addresses");
						} else {
							//does not contain
							freedAndNotReusedMemory.put(traceEntry.getAddress(), traceEntry);
						}
						
					} else {
						//not expected, but can happen since we are not monitoring all allocations from the beginning of the execution
												
						//log this stack that did a free on unallocated memory
						freeUnallocagedMemoryStacks.add(traceEntry);
						
						if (freedAndNotReusedMemory.containsKey(traceEntry.getAddress())) {
							//System.out.println("adding to doubleFree list:"+traceEntry.getAddress());
							//double free! log the error
							doubleFree.add(traceEntry);
						} else {
							//System.out.println("adding to freeMemory map:"+traceEntry.getAddress());
							//log the address that the free was done
							freedAndNotReusedMemory.put(traceEntry.getAddress(), traceEntry);
						}
						
					}

				} else {
					throw new IOException("Cannot handle entry type:"+traceEntry.getType());
				}
				
			}
			
			totalDoubleFreeStacks = doubleFree.size();			
			
			//find unique cases for qrong deletes and store them			
			for (MemoryAllocatorTraceEntry entry : doubleFree) {
				boolean found = false;
				for (StackOccurence reportEntry : uniqueDoubleFreeStacks) {
					if (reportEntry.getStack().equals(entry.getCallStack())) {
						found = true;
						//increase counter
						reportEntry.increaseTimesFound();						
						break;
					}
				}
				if (!found) {
					uniqueDoubleFreeStacks.add(new StackOccurence(entry.getCallStack()));
				} 
			}
						
			
			//sort list according to times found
			Collections.sort(uniqueDoubleFreeStacks, new Comparator<StackOccurence> () {
				@Override
				public int compare(StackOccurence o1,
						StackOccurence o2) {
					return o2.getTimesFound()-o1.getTimesFound();
				}				
			});
			
			
			//now process deletes on wrong addresses. 		
			totalPotentialWrongFreeSuspects = freeUnallocagedMemoryStacks.size();
			for (MemoryAllocatorTraceEntry entry : freeUnallocagedMemoryStacks) {
				boolean found = false;
				for (StackOccurence reportEntry : uniquePotentialWrongFreeStacks) {
					if (reportEntry.getStack().equals(entry.getCallStack())) {
						found = true;
						//increase counter
						reportEntry.increaseTimesFound();						
						break;
					}
				}
				if (!found) {
					uniquePotentialWrongFreeStacks.add(new StackOccurence(entry.getCallStack()));
				} 
			}
						
			
			//sort based on frequency
			Collections.sort(uniquePotentialWrongFreeStacks, new Comparator<StackOccurence>() {

				@Override
				public int compare(StackOccurence o1, StackOccurence o2) {					
					return o2.getTimesFound() - o1.getTimesFound();
				}
				
			});
			
			//for each unique unallocated delete stack, now find the ones that have never freed successfully memory
			for (StackOccurence entry :uniquePotentialWrongFreeStacks) {
				boolean found = false;
				for (MemoryAllocatorTraceEntry sucDeleteEntry : uniqueSuccessfulFreeStacks) {
					if (sucDeleteEntry.getCallStack().equals(entry.getStack())) {
						found = true;
						break;
					}
				}
				if (!found) {
					//this stack has never correctly freed / deleted memory
					uniquePotentialWrongFreeStacksNeverCorrectlyFreed.add(entry);
				}
			}
			
			//second step, analyze non empty memory allocations on the map to find unique call stacks
			totalPoteltialLeakSuspects = memoryAllocation.keySet().size();
			for (String memoryAddress : memoryAllocation.keySet()) {
				MemoryAllocatorTraceEntry unallocatedMemoryCallStack = memoryAllocation.get(memoryAddress);
				boolean found = false;
				for (StackOccurence uniquePLeak :uniquePotentialLeakStacks) {
					if (uniquePLeak.getStack().equals(unallocatedMemoryCallStack.getCallStack())) {
						found = true;
						uniquePLeak.increaseTimesFound();
						break;
					}
				}
				if (!found) {
					//insert for the first time
					uniquePotentialLeakStacks.add(new StackOccurence(unallocatedMemoryCallStack.getCallStack()));
				}
			}
			
			//sort based on frequency
			Collections.sort(uniquePotentialLeakStacks, new Comparator<StackOccurence>() {

				@Override
				public int compare(StackOccurence o1, StackOccurence o2) {					
					return o2.getTimesFound() - o1.getTimesFound();
				}
				
			});
			
			//now calculate from the potential leaks, the ones that have never been freed
			for (StackOccurence entry :uniquePotentialLeakStacks) {
				boolean found = false;
				for (MemoryAllocatorTraceEntry sucDeletedStackEntry : uniqueSuccessfullyDeletedStacks) {
					if (sucDeletedStackEntry.getCallStack().equals(entry.getStack())) {
						found = true;
						break;
					}
				}
				if (!found) {
					//this stack has never correctly freed / deleted memory
					uniquePotentialLeakStacksNeverFreed.add(entry);
				}
			}	

			//calculate combined suspect leak stack
			
			if (uniquePotentialLeakStacks.size() > 1) {
				//initial conditions for the combined common stack print 
				int stackDepth = 0;	
				//create initial positions array (all of them)
				Integer[] positions = new Integer[uniquePotentialLeakStacks.size()];
				for (int i=0;i<positions.length;i++) {
					positions[i]=i;
				}			
				combinedLeakStackSuspects = getMergedMemoryAllocatorStack(stackDepth, positions, uniquePotentialLeakStacks);
			}
			
			//calculate combined strongly suspect leak stack
			if (uniquePotentialLeakStacksNeverFreed.size() > 1) {
				int stackDepth = 0;
				Integer[] positions = new Integer[uniquePotentialLeakStacksNeverFreed.size()];
				for (int i=0;i<positions.length;i++) {
					positions[i]=i;
				}					
				combinedLeakStackStrongSuspects = getMergedMemoryAllocatorStack(stackDepth, positions, uniquePotentialLeakStacksNeverFreed);
			}

			
		}catch (IOException e) {
			System.out.println("problem reading input (traces) file:"+e.getMessage());
			
			throw e;
		} 
	}
	
	/**
	 * Performs the traces analysis for a generic program (using free/malloc/realloc/calloc)
	 * @throws IOException 
	 */
	public void performBrkAnalysis() throws IOException {				

		//current break address (used to calculate growths and shrinks)
		long currentBrkAddress = 0;

		//list to keep stacks that allocated / deallocated memory
		List<BrkTraceEntry> brkAllocationStacks = new ArrayList<BrkTraceEntry>();
		List<BrkTraceEntry> brkDeAllocationStacks = new ArrayList<BrkTraceEntry>();
		List<BrkTraceEntry> failedBrkCalls = new ArrayList<BrkTraceEntry>();
		List<BrkTraceEntry> noIncreaseCalls = new ArrayList<BrkTraceEntry>();
		
		//open the traces file and process each line 
		try (BufferedReader br = new BufferedReader(new FileReader(inFile))) {
			
			//read all entries
			BrkTraceEntry traceEntry = null;			
			while ((traceEntry = readBrkTraceEntry(br)) != null) {

				//now process the entry
				if (traceEntry.getType().equals(BrkTraceEntryType.BRK)) {
					if (traceEntry.isSuccess()) {
						if (currentBrkAddress == 0) {
							//first time 
							currentBrkAddress = Long.decode(traceEntry.getAddress());						
						} else {
							//we already have a break address
							//decode new brk address
							long newBrkAddress = Long.decode(traceEntry.getAddress());
							//calculate mem increase
							long memIncrease = newBrkAddress - currentBrkAddress;
							//store new current brk address
							currentBrkAddress = newBrkAddress;
							
							if (memIncrease == 0) {
								noIncreaseCalls.add(traceEntry);
							} else if (memIncrease < 0) {
								brkDeAllocationStacks.add(traceEntry);		
							} else if (memIncrease > 0) {
								brkAllocationStacks.add(traceEntry);
							}
						}
					} else {
						//failed brk call
						failedBrkCalls.add(traceEntry);
					}
					
				} else if (traceEntry.getType().equals(BrkTraceEntryType.SBRK)) {
					if (traceEntry.isSuccess()) {
						
						long previousBrkAddress = Long.decode(traceEntry.getAddress());
						long memIncrease = traceEntry.getSize();

						long newBrkAddress = previousBrkAddress + memIncrease;
						//store new current brk address
						currentBrkAddress = newBrkAddress;
						
						if (memIncrease == 0) {
							noIncreaseCalls.add(traceEntry);
						} else if (memIncrease < 0) {
							brkDeAllocationStacks.add(traceEntry);		
						} else if (memIncrease > 0) {
							brkAllocationStacks.add(traceEntry);
						}

					} else {
						//failed brk call
						failedBrkCalls.add(traceEntry);
					}
				} else {
					throw new IOException("Cannot handle entry type:"+traceEntry.getType());
				}
				
			}
			
			//now we need to process all decoded entries
			//calculate totals
			totalBrkIncreaseStacks = brkAllocationStacks.size();
			totalBrkDecreaseStacks = brkDeAllocationStacks.size();
			totalBrkNeutralStacks = noIncreaseCalls.size();
			totalBrkFailedStacks = failedBrkCalls.size();
			
			//now get unique failed stacks
			for (BrkTraceEntry entry : failedBrkCalls) {
				//see if this already exists on the unique list
				boolean found = false;
				for (int i=0;i<uniqueFailedBrkStacks.size();i++) {
					BrkStackOccurence uniqueEntry = uniqueFailedBrkStacks.get(i);
					if (uniqueEntry.getStack().equals(entry.getCallStack())) {
						found = true;
						//increse counters
						uniqueEntry.increaseTimesFound();
						uniqueEntry.increaseSize(entry.getSize());
						break;
					}
				}
				if (!found) {
					//add
					uniqueFailedBrkStacks.add(new BrkStackOccurence(entry.getCallStack(), entry.getSize()));
				} 
			}
			
			//calculate unique brk stacks
			List<BrkTraceEntry> allBrkStacks =  new ArrayList<BrkTraceEntry>();
			allBrkStacks.addAll(brkAllocationStacks);
			allBrkStacks.addAll(brkDeAllocationStacks);
			
			for (BrkTraceEntry entry : allBrkStacks) {
				//see if this already exists on the unique list
				boolean found = false;
				for (int i=0;i<uniqueBrkStacks.size();i++) {
					BrkStackOccurence uniqueEntry = uniqueBrkStacks.get(i);
					if (uniqueEntry.getStack().equals(entry.getCallStack())) {
						found = true;
						//increse counters
						uniqueEntry.increaseTimesFound();
						uniqueEntry.increaseSize(entry.getSize());
						break;
					}
				}
				if (!found) {
					//add
					uniqueBrkStacks.add(new BrkStackOccurence(entry.getCallStack(), entry.getSize()));
				} 
			}
			
			//sort per appearance frequency
			Collections.sort(uniqueBrkStacks, new Comparator<BrkStackOccurence>() {
				@Override
				public int compare(BrkStackOccurence o1,
						BrkStackOccurence o2) {					
					return o2.getTimesFound()-o1.getTimesFound();
				}
				
			});
			
			//initial conditions for the combined common stack print 
			int stackDepth = 0;	
			//create initial positions array (all of them)
			Integer[] positions = new Integer[uniqueBrkStacks.size()];
			for (int i=0;i<positions.length;i++) {
				positions[i]=i;
			}			
			combinedBrkStacks = getMergedBrkStack(stackDepth, positions, uniqueBrkStacks);

			
		}catch (IOException e) {
			System.out.println("problem reading input (traces) file:"+e.getMessage());
			
			throw e;
		} 
	}	
	
	/**
	 * Performs the traces analysis for processed files 
	 * (produced by trace-malloc-free-prod.d)
	 * @param stackRelationships 
	 * @throws IOException 
	 */
	public void performProcessedFileAnalysis(Map<StackOccurence, List<StackOccurence>> stackRelationships) throws IOException {		
		
		//open the traces file and process each line 
		try (BufferedReader br = new BufferedReader(new FileReader(inFile))) {

			positionNextEntryOnProcessedFile(br);
			positionNextEntryOnProcessedFile(br);
			
			//read all entries, first we have the allocation stacks
			StackOccurence traceEntry = null;			
			while ((traceEntry = readProcessedTraceEntry(br)) != null) {
				//we might have top level memory allocator calls twice, because of their different return addresses
				boolean found = false;
				for (StackOccurence existingAllocStack : uniqueAllocationStacks) {
					if (existingAllocStack.getStack().equals(traceEntry.getStack())) {
						//already exists, increase
						existingAllocStack.increaseTimesFound(traceEntry.getTimesFound());
						found = true;
						break;
					}
				}
				if (!found) {
					//first time
					uniqueAllocationStacks.add(traceEntry);
				} 
			}
					
			//now the deallocation stacks
			while ((traceEntry = readProcessedTraceEntry(br)) != null) {
				//we might have top level memory allocator calls twice, because of their different return addresses			
				boolean found = false;
				for (StackOccurence existingDeAllocStack : uniqueDeallocationStacks) {
					if (existingDeAllocStack.getStack().equals(traceEntry.getStack())) {
						//already exists, increase
						existingDeAllocStack.increaseTimesFound(traceEntry.getTimesFound());
						found = true;
						break;
					}
				}
				if (!found) {
					//first time
					uniqueDeallocationStacks.add(traceEntry);
				}
			}
			
			//copy all of them, they will eventually be removed as they are located
			uniqueUnfreedAllocationStacks.addAll(uniqueAllocationStacks);
			
			//for each free
			//String matchFree = "MONHND.exe`__1cPI2_MONHND_ToposEnext6M_pnbAI1_MONHND_UpdateableObject__+0x5c";
			//String matchAllocation = "MONHND.exe`__1cGDLList4CI_Jins_after6MpvrkI_1_+0x48";
			
			for (StackOccurence uniqueDeallocationStack : uniqueDeallocationStacks) {
				//if (uniqueDeallocationStack.getStack().contains(matchFree)) {
				//	System.out.println("Examining stack ("+uniqueDeallocationStack.getTimesFound()+") \n"+uniqueDeallocationStack.getStack());																						
				//}
				//check if we have found a match of it
				boolean foundDeallocationStack = false;
				for (StackOccurence freeRelationshipStack : stackRelationships.keySet()) {
					
					if (uniqueDeallocationStack.getStack().equals(freeRelationshipStack.getStack())) {
						//System.out.println("\nLocated deallocation stack in relationships:\n"+uniqueDeallocationStack.getStack()+"\n");

						//found match
						foundDeallocationStack=true;
						//get all stacks that this free released memory from
						List<StackOccurence> relatedAllocations = stackRelationships.get(freeRelationshipStack);
						for (StackOccurence relatedAllocationStack : relatedAllocations) {
							//if (uniqueDeallocationStack.getStack().contains(matchFree)) {
							//	System.out.println("Examining related allocation stack ("+relatedAllocationStack.getTimesFound()+") \n"+relatedAllocationStack.getStack());																													
							//}
							//check all allocation stacks
							List<StackOccurence> foundStacks = new ArrayList<StackOccurence>();
							for (StackOccurence unfreedAllocationStack : uniqueUnfreedAllocationStacks) {
								/* workaround for some .d scripts 
								if (unfreedAllocationStack.getStack().equals(relatedAllocationStack.getStack().replaceAll("malloc\\+0x64", "malloc"))) {									
									foundStacks.add(unfreedAllocationStack);
								}*/
								//System.out.println("\n### Comparing \n"+unfreedAllocationStack.getStack()+"\n\n with:\n"+relatedAllocationStack.getStack());
								if (unfreedAllocationStack.getStack().equals(relatedAllocationStack.getStack())) {									
									foundStacks.add(unfreedAllocationStack);
									//System.out.println("\n***Found match***\n");
								} else {
									
								}
								
							}
							//remove all found
							uniqueUnfreedAllocationStacks.removeAll(foundStacks);
						}
					} 
				}
				if (!foundDeallocationStack) {
					//add to unknown free stacks
					uniqueUnknownDeallocationStacks.add(uniqueDeallocationStack);
					//System.out.println("\n==>Did not locate deallocation stack in relationships:\n"+uniqueDeallocationStack.getStack()+"\n");
					
				}
			}
			
			
		}catch (IOException e) {
			System.out.println("problem reading input (traces) file:"+e.getMessage());
			
			throw e;
		} 
	}
	
	
	/**
	 * This method combines the information from all unique call stacks to show all memory that was allocated 
	 * and from which place. It is a different look at the same data, combining the call stacks to see their relation
	 * @param stackDepth the stack depth, start with 0
	 * @param elementPositions pointers to the element positions
	 * @param stackElements the stack elements
	 * @throws IOException in case a stack trace has unexpected data
	 */
	private String getMergedMemoryAllocatorStack(int stackDepth, Integer[] elementPositions, List<StackOccurence> stackElements) throws IOException {			
		//all elements have the same stack up to here. 
		
		//check if we reached a leaf
		if (elementPositions.length == 1) {
			//this is a leaf
			StackOccurence leafStackEntry = stackElements.get(elementPositions[0]);
			String[] leafStack =  getCallStack(leafStackEntry.getStack());
			//create the formatted stack lines
			StringBuffer stackLines = new StringBuffer();
			for (int i=stackDepth;i<leafStack.length;i++) {				
				//insert appropriate number of tabs
				for (int j=0;j<i;j++) {
					stackLines.append("\t");									
				}			
				stackLines.append(leafStack[i]);				
				if (i==leafStack.length-1) {
					//last one 
					stackLines.append("\t***** Found  "+leafStackEntry.getTimesFound()+"  times *****");
				}
				stackLines.append("\n");
			}
			//stop recursion in this direction, reached a leaf
			return stackLines.toString();
		}
		
		//OK we have more than one in the set. going-on
		
		//print current stack level
		StringBuffer combinedStackLines = new StringBuffer();
		for (int j=0;j<stackDepth;j++) {
			combinedStackLines.append("\t");									
		}
		combinedStackLines.append(getCallStack(stackElements.get(elementPositions[0]).getStack())[stackDepth]);
		combinedStackLines.append("\n");
		
		//examine next stack depth for the selected positions
		Map<String, List<Integer>> commonStackSets = new HashMap<String, List<Integer>>();
		for (int pos : elementPositions) {
			
			//examine all elements and split into sets that have the same stack at this level			
			StackOccurence stackReportEntry = stackElements.get(pos);			
			String[] callStack = getCallStack(stackReportEntry.getStack());
			if (callStack.length < stackDepth+1) {
				//this stack has reached its end. Should not happen?
				throw new IOException("Found stack that does not have a next element:\n"+stackReportEntry+"\n");	
			} else {
				//OK we go in it has a next element
				//get the next stack element
				String currentStackElement = callStack[stackDepth+1];
				if (commonStackSets.containsKey(currentStackElement)) {
					//System.out.println("common stack array contains key");
					commonStackSets.get(currentStackElement).add(pos);
				} else {
					//first one
					List<Integer> elementPointers = new ArrayList<Integer>();
					elementPointers.add(pos);
					commonStackSets.put(currentStackElement, elementPointers);
				}
			}
		}
		
		//recursively go through the next stack level 
		for (String commonStackKey : commonStackSets.keySet()) {
			Integer[] intArrayType = new Integer[0];
			combinedStackLines.append(getMergedMemoryAllocatorStack(stackDepth+1, commonStackSets.get(commonStackKey).toArray(intArrayType), stackElements)).toString();				
		}					
		
		return combinedStackLines.toString();
	}
	
	/**
	 * This method combines the information from all unique call stacks to show all memory that was allocated 
	 * and from which place. It is a different look at the same data, combining the call stacks to see their relation
	 * @param stackDepth the stack depth, start with 0
	 * @param elementPositions pointers to the element positions
	 * @param stackElements the stack elements
	 * @throws IOException in case a stack trace has unexpected data
	 */
	private String getMergedBrkStack(int stackDepth, Integer[] elementPositions, List<BrkStackOccurence> stackElements) throws IOException {			
		//all elements have the same stack up to here. 
		//System.out.println("combinedPrintStackDepth: depth:"+stackDepth+" elements:"+elementPositions.length);
		
		//check if we reached a leaf
		if (elementPositions.length == 1) {
			//this is a leaf
			BrkStackOccurence leafStackEntry = stackElements.get(elementPositions[0]);
			String[] leafStack =  getCallStack(leafStackEntry.getStack());
			//create the formatted stack lines
			StringBuffer stackLines = new StringBuffer();
			for (int i=stackDepth;i<leafStack.length;i++) {				
				//insert appropriate number of tabs
				for (int j=0;j<i;j++) {
					stackLines.append("\t");									
				}			
				stackLines.append(leafStack[i]);				
				if (i==leafStack.length-1) {
					//last one 
					stackLines.append("\t***** "+leafStackEntry.getInformation()+" *****");
				}
				stackLines.append("\n");
				//logMessage(logMsg.toString(), writer, false);	
			}
			//stop recursion in this direction, reached a leaf
			return stackLines.toString();
		}
		
		//OK we have more than one in the set. going-on
		
		//print current stack level
		StringBuffer combinedStackLines = new StringBuffer();
		for (int j=0;j<stackDepth;j++) {
			combinedStackLines.append("\t");									
		}
		combinedStackLines.append(getCallStack(stackElements.get(elementPositions[0]).getStack())[stackDepth]);
		combinedStackLines.append("\n");
		
		//examine next stack depth for the selected positions
		Map<String, List<Integer>> commonStackSets = new HashMap<String, List<Integer>>();
		for (int pos : elementPositions) {
			
			//examine all elements and split into sets that have the same stack at this level			
			BrkStackOccurence stackReportEntry = stackElements.get(pos);			
			String[] callStack = getCallStack(stackReportEntry.getStack());
			if (callStack.length < stackDepth+1) {
				//this stack has reached its end. Should not happen?
				throw new IOException("Found stack that does not have a next element:\n"+stackReportEntry+"\n");	
			} else {
				//OK we go in it has a next element
				//get the next stack element
				String currentStackElement = callStack[stackDepth+1];
				if (commonStackSets.containsKey(currentStackElement)) {
					//System.out.println("common stack array contains key");
					commonStackSets.get(currentStackElement).add(pos);
				} else {
					//first one
					//System.out.println("common stack array does not contain key");
					List<Integer> elementPointers = new ArrayList<Integer>();
					elementPointers.add(pos);
					commonStackSets.put(currentStackElement, elementPointers);
				}
			}
		}
		
		//recursively go through the next stack level 
		for (String commonStackKey : commonStackSets.keySet()) {
			Integer[] intArrayType = new Integer[0];
			combinedStackLines.append(getMergedBrkStack(stackDepth+1, commonStackSets.get(commonStackKey).toArray(intArrayType), stackElements)).toString();				
		}					
		
		return combinedStackLines.toString();
	}	
	
	/**
	 * Returns the callstack as a String array
	 * @param callstack the callstack with new lines as a single string
	 * @return the callstack as a string array
	 */
	private String[] getCallStack(String callstack) {
		String[] stackEntries = callstack.split("\n");
		String[] reversedStackEntries = reverseStackEntries(stackEntries);		
		return reversedStackEntries;
	}
	
	/**
	 * Simpy reverses the stack entries
	 * @param stackEntries 
	 * @return
	 */
	private String[] reverseStackEntries (String[] stackEntries) {
		String[] ret = new String[stackEntries.length];
		for (int i=0;i<stackEntries.length;i++) {
			ret[i] = stackEntries[stackEntries.length-(i+1)];
		}
		return ret;
	}

	/**
	 * logs a message to the log file and system out of the passed parameter is true
	 * @param writer
	 * @param systemOut
	 */
	public static void logMessage(String message, boolean systemOut, PrintWriter writer) {
		writer.println(message);
		if (systemOut) {
			System.out.println(message);
		}
	}
	

	/**
	 * reads the next log entry from the file, for a generic file
	 * @param br
	 * @return
	 * @throws IOException
	 */
	public static MemoryAllocatorTraceEntry readMemoryAllocatorTraceEntry(BufferedReader br) throws IOException{
		
		List<String> entryLines = new ArrayList<String>();
		
		String line;
		boolean processingEntry = false;
		while ((line = br.readLine()) != null) {
			
			if (line.contains(entryStartCharSequence)) {
				//sanity check
				if (processingEntry) {
					throw new IOException("Trace file corrupted. Found char sequence:"+entryStartCharSequence+" while already processing trace entry. Current line:"+line);
				} else {
					//mark beginning of processing a new trace entry
					processingEntry = true;
					
					//found start sequence 
					entryLines.add(line);
					
					//check if it is a single line
					if (line.contains(entryEndCharSequence)) {
						//mark end of processing entry
						processingEntry = false;
						return new MemoryAllocatorTraceEntry(entryLines);
					}
				}
			} else {				
				//line does not contain start sequence
				if (processingEntry) {
					if (!line.trim().equals("")) {
						//if we have a non-empty line, add it
						entryLines.add(line);
					}
				}
				
				//check if contains the end sequence
				if (line.contains(entryEndCharSequence)) {
					//sanity check
					if (!processingEntry) {
						throw new IOException("Trace file corrupted. Found char sequence:"+entryEndCharSequence+" while not processing a trace entry. Current line:"+line);					
					}
					
					//mark end of processing entry
					processingEntry = false;
					return new MemoryAllocatorTraceEntry(entryLines);
				}
			}
											
		}
		//reached end of file
		return null;
	}
	
	/**
	 * reads the next log entry from the file, for a generic file
	 * @param br
	 * @return
	 * @throws IOException
	 */
	public BrkTraceEntry readBrkTraceEntry(BufferedReader br) throws IOException{
		
		List<String> entryLines = new ArrayList<String>();
		
		String line;
		boolean processingEntry = false;
		while ((line = br.readLine()) != null) {
			
			if (line.contains(entryStartCharSequence)) {
				//sanity check
				if (processingEntry) {
					throw new IOException("Trace file corrupted. Found char sequence:"+entryStartCharSequence+" while already processing trace entry. Current line:"+line);
				} else {
					//mark beginning of processing a new trace entry
					processingEntry = true;
					
					//found start sequence 
					entryLines.add(line);
					
					//check if it is a single line
					if (line.contains(entryEndCharSequence)) {
						//mark end of processing entry
						processingEntry = false;
						return new BrkTraceEntry(entryLines);
					}
				}
			} else {				
				//line does not contain start sequence
				if (processingEntry) {
					if (!line.trim().equals("")) {
						//if we have a non-empty line, add it
						entryLines.add(line);
					}
				}
				
				//check if contains the end sequence
				if (line.contains(entryEndCharSequence)) {
					//sanity check
					if (!processingEntry) {
						throw new IOException("Trace file corrupted. Found char sequence:"+entryEndCharSequence+" while not processing a trace entry. Current line:"+line);					
					}
					
					//mark end of processing entry
					processingEntry = false;
					return new BrkTraceEntry(entryLines);
				}
			}
											
		}
		//reached end of file
		return null;
	}
		
	
	/**
	 * reads the next log entry from the file (processed file)
	 * @param br
	 * @return
	 * @throws IOException
	 */
	public StackOccurence readProcessedTraceEntry(BufferedReader br) throws IOException{
		List<String> entryLines = new ArrayList<String>();
		
		String line;
		boolean processingEntry = false;
		while ((line = br.readLine()) != null) {
			//System.out.println("read entry: reading line:"+line);
			if (line.trim().equals("") && (!processingEntry)) {
				//go on next line
				continue;
			} else if (line.trim().equals("") && processingEntry) {
				break;
			} else {
				if (line.trim().startsWith("==")) {
					//found end of section
					return null;
				} else {
					processingEntry = true;
					entryLines.add(line.trim());
				}
			}										
		}
		
		//convert entry & return
		StringBuffer stackSB = new StringBuffer();
		Integer times = null;
		
		for (int i=0;i<entryLines.size();i++) {
			if (i==entryLines.size()-1) {
				///last line is the number of times
				times = Integer.parseInt(entryLines.get(i));
			} else {
				stackSB.append(entryLines.get(i)+"\n");
			}
		}
		
		return new StackOccurence(clearTopLevelStackReturnPointer(stackSB.toString()), times);

	}	

	/**
	 * Method that clears the return address of the top level call,
	 * i.e. malloc+064 ==> malloc
	 * @param stack the string that is the stack
	 * @return
	 */
	public static String clearTopLevelStackReturnPointer(String stack) {
		StringBuffer ret = new StringBuffer();
		String[] stackLines = stack.split("\n");
		for (int i=0;i<stackLines.length;i++) {
			if (i == 0) {
				//top level stack element, only work here
				ret.append(stackLines[0].replaceAll("\\+.+", "")); //i.e. malloc+064 ==> malloc
				if (i != (stackLines.length-1)) {
					ret.append("\n");
				}
			} else {
				if (!stackLines[i].isEmpty()) {
					ret.append(stackLines[i]);
					if (i != (stackLines.length-1)) {
						ret.append("\n");
					}
				}
			}
		}
		return ret.toString();
	}
	/**
	 * positions the reader on the first entry
	 * @param br the reader
	 * @throws IOException if it cannot position on the next entry
	 */
	private void positionNextEntryOnProcessedFile(BufferedReader br) throws IOException{
		String line;
		
		while ( (line = br.readLine() ) != null ) {
			//System.out.println("position: reading line:"+line);
			if (line.trim().equals("")) {
				//go on next line
				continue;
			} else if (line.trim().startsWith("==")) {
				break;
			} else {
				//wrong.....
				throw new IOException("Cannot determine file position");
			}
		}
	}
	
	/**
	 * Prints the analysis information
	 */
	public void printAnalysisInformation(TraceFileType fileType) {
		switch (fileType) {
		
		case MEMALLOC : {
			//to plevel info
			logMessage("Call statistics", true, writer);
			logMessage("Found "+totalMallocCalls+" malloc calls", true, writer);
			logMessage("Found "+totalCallocCalls+" calloc calls", true, writer);
			logMessage("Found "+totalReallocCalls+" realloc calls", true, writer);
			logMessage("Found "+totalFreeCalls+" free calls", true, writer);
			//wrong delete stacks
			logMessage("\nDouble free issues", true, writer);
			logMessage("Found "+totalDoubleFreeStacks+" double free stacks in total", true, writer);
			if (totalDoubleFreeStacks > 0) {
				logMessage("Found "+uniqueDoubleFreeStacks.size()+" unique double free stacks", true, writer);
				for (StackOccurence dFreeStack : uniqueDoubleFreeStacks) {
					logMessage("Found double free stack "+dFreeStack.getTimesFound()+" times. Stack:\n"+dFreeStack.getStack()+"\n", false, writer);				
				}
				
			}			
			
			logMessage("\nFree non-allocated memory issues (may also be potential memory leaks)", true, writer);			
			//free on unallocated memory (may be an issue, or not)			
			logMessage("Found "+totalPotentialWrongFreeSuspects+" stacks that freed memory that was not allocated during the period of the trace", true, writer);
			logMessage("Found "+uniquePotentialWrongFreeStacks.size()+" unique stacks that freed memory that was not allocated during the period of the trace", true, writer);
			logMessage("Found "+uniqueSuccessfulFreeStacks.size()+" unique stacks that correctly freed memory", true, writer);
			logMessage("Found "+uniquePotentialWrongFreeStacksNeverCorrectlyFreed.size()+" unique stacks that have never been found to correctly free memory", true, writer);
			logMessage("Suspected wrong free stacks\n",false, writer);
			for (StackOccurence delUnallocatedStack : uniquePotentialWrongFreeStacks) {
				logMessage("Suspected wrong free stack found "+delUnallocatedStack.getTimesFound()+" times",false, writer);
				logMessage(delUnallocatedStack.getStack()+"\n\n",false, writer);
			}
			
			logMessage("Strongly suspected wrong free stacks\n",false, writer);
			for (StackOccurence delUnallocatedStack : uniquePotentialWrongFreeStacksNeverCorrectlyFreed) {
				logMessage("Strongly suspected wrong free stack found "+delUnallocatedStack.getTimesFound()+" times",false, writer);
				logMessage(delUnallocatedStack.getStack()+"\n\n",false, writer);
			}
			
			//potential memory leaks
			logMessage("\nMemory leak issues", true, writer);
			logMessage("Found "+totalPoteltialLeakSuspects+" potential memory leaks in total", true, writer);
			logMessage("Found "+uniquePotentialLeakStacks.size()+" unique potential memory leak stacks (suspects)", true, writer);
			logMessage("Found "+uniqueSuccessfullyDeletedStacks.size()+" unique stacks that allocated memory that was correctly freed", true, writer);
			logMessage("Found "+uniquePotentialLeakStacksNeverFreed.size()+" unique stacks that were never correctly deleted/freed (strong suspects)\n", true, writer);
			
			int totalUndeletedAllocations = 0;
			//here we are showing the leak stacks based on their frequency 
			
			for (StackOccurence suspectCallStack : uniquePotentialLeakStacks) {
				logMessage("Suspect leak stack found "+suspectCallStack.getTimesFound()+" times",false, writer);
				totalUndeletedAllocations += suspectCallStack.getTimesFound();
				logMessage(suspectCallStack.getStack()+"\n\n",false, writer);
			}

			for (StackOccurence suspectCallStack : uniquePotentialLeakStacksNeverFreed) {
				logMessage("Strongly suspect leak stack found "+suspectCallStack.getTimesFound()+" times",false, writer);
				logMessage(suspectCallStack.getStack()+"\n\n",false, writer);
			}

			if (totalUndeletedAllocations != totalPoteltialLeakSuspects) {
				//total undeleted allocations			
				logMessage("(Warn) Found mispatch in counting total memory allocations that were not deleted. From pre-processing: "+totalPoteltialLeakSuspects+" from each individual stack count:"+totalUndeletedAllocations+"\n", true, writer);
			}

			//combined stacks
			if (!combinedLeakStackSuspects.isEmpty()) {
				logMessage("Presenting memory leak suspects in a combined call stack\n", false, writer);
				logMessage(combinedLeakStackSuspects, false, writer);
			}
			//combined stacks
			if (!combinedLeakStackStrongSuspects.isEmpty()) {
				logMessage("Presenting strong memory leak suspects in a combined call stack\n", false, writer);
				logMessage(combinedLeakStackStrongSuspects, false, writer);
			}			
			break;
		}
		
		case BRK : {
			logMessage("\nCall statistics\n", true, writer);
			logMessage("Found "+totalBrkIncreaseStacks+" brk calls that increased the process virtual memory", true, writer);
			logMessage("Found "+totalBrkDecreaseStacks+" brk calls that decreased the process virtual memory", true, writer);
			logMessage("Found "+totalBrkNeutralStacks+" brk calls that were neutral in terms of memory", true, writer);
			logMessage("Found "+totalBrkFailedStacks+" brk calls that failed", true, writer);
			logMessage("Found in total "+uniqueBrkStacks.size()+" unique brk stacks", true, writer);

			if (totalBrkFailedStacks>0) {
				logMessage("\n*** Failed brk calls (unsuccessful memory increase requests) ***\n", true, writer);			
				for (BrkStackOccurence failedBrkStacks : uniqueFailedBrkStacks) {
					logMessage("Failed brk stack found "+failedBrkStacks.getTimesFound()+" times, total size:"+failedBrkStacks.getSizeIncrease(),false, writer);
					logMessage(failedBrkStacks.getStack()+"\n\n",false, writer);
				}
			}
			
			logMessage("\n*** Unique brk call stacks ***\n", false, writer);						
			for (BrkStackOccurence failedBrkStacks : uniqueBrkStacks) {
				logMessage("Unique brk stack found "+failedBrkStacks.getTimesFound()+" times, total size:"+failedBrkStacks.getSizeIncrease(),false, writer);
				logMessage(failedBrkStacks.getStack()+"\n\n",false, writer);
			}
			
			//combined stack
			logMessage("Presenting brk stacks in a combined call stack\n", false, writer);
			logMessage(combinedBrkStacks, false, writer);			
			
			break;
		}
		
		default : {
		}
		}

		writer.close();
	}
	




	/**
	 * Prints a combined analysis results from a set of results files
	 * @param fileAnalysisResults the map with the files and their analysis results
	 * @param fileOut the output file to be used
	 * @throws UnsupportedEncodingException 
	 * @throws FileNotFoundException 
	 */
	public static void printMemoryAllocatorCombinedAnalysisResults(Map<File, DTLeakAnalyzer> fileAnalysisResults, String fileOut) throws FileNotFoundException, UnsupportedEncodingException {
		PrintWriter combinedFileWrite = new PrintWriter(fileOut, "UTF-8");		
		
		File[] files = fileAnalysisResults.keySet().toArray(new File[]{});
		Arrays.sort(files, new Comparator<File>() {
			@Override
			public int compare(File o1, File o2) {
				return o1.getName().compareTo(o2.getName());
			}
			
		});
		
		StringBuffer fileNamesSb = new StringBuffer();
		for (int i=0;i<files.length;i++) {	
			fileNamesSb.append(files[i].getName()+" {"+i+"}");
			fileNamesSb.append("\n");
		}
		fileNamesSb.append("\n");
		DTLeakAnalyzer.logMessage("Combined memory allocator analysis for files:\n"+fileNamesSb, false, combinedFileWrite);

		//get all results

		//double free
		DTLeakAnalyzer.logMessage("\n\n*** Double free cases ***\n\n", false, combinedFileWrite);
		//for each processed file
		for (int i=0;i<files.length;i++) {		
			DTLeakAnalyzer traceAnalysis = fileAnalysisResults.get(files[i]);
			
			//get all the wrong delete reports
			for (StackOccurence doubleFreeStack: traceAnalysis.uniqueDoubleFreeStacks) {
				//write to a buffer so far how many times this wrong delete stack is found
				StringBuffer doubleFreeTimesFound = new StringBuffer();
				for (int k=0;k<i;k++) {
					//previous ones do not have it, as we search forward and when we find a match we remove it
					doubleFreeTimesFound.append("{"+k+"}=0, ");
				}
				doubleFreeTimesFound.append("{"+i+"}="+doubleFreeStack.getTimesFound()+", ");
				
				//go through the rest of the files and check how many times it is there 
				for (int j=i+1; j<files.length;j++) {
					DTLeakAnalyzer otherTraceAnalysis = fileAnalysisResults.get(files[j]);
					boolean found = false;
					//for each wrong delete reports in other file
					INNER_LOOP:
					for (int owdsIndex=0;owdsIndex<otherTraceAnalysis.uniqueDoubleFreeStacks.size();owdsIndex++) {
						StackOccurence otherDoubleFree = otherTraceAnalysis.uniqueDoubleFreeStacks.get(owdsIndex);
						
						if (doubleFreeStack.getStack().equals(otherDoubleFree.getStack())) {
							//found match, the same wrong delete stack
							found = true;
							doubleFreeTimesFound.append("{"+j+"}="+otherDoubleFree.getTimesFound()+", ");
							//remove from other list as not to process it again
							otherTraceAnalysis.uniqueDoubleFreeStacks.remove(owdsIndex);
							break INNER_LOOP;
						}
					}
					if (!found) {
						doubleFreeTimesFound.append("{"+j+"}=0, ");
					}
				}
				logMessage("Found double free stack "+doubleFreeTimesFound+" times. Stack:\n"+doubleFreeStack.getStack()+"\n", false, combinedFileWrite);
				
			}			
		}
		
		
		DTLeakAnalyzer.logMessage("\n\n*** Suspected wrong free cases (stacks that freed memory that was not allocated during the tracing)***\n\n", false, combinedFileWrite);
		//for each processed file
		for (int i=0;i<files.length;i++) {		
			DTLeakAnalyzer traceAnalysis = fileAnalysisResults.get(files[i]);
						
			//get all the potential leaks
			for (StackOccurence wrongDeleteCandidate: traceAnalysis.uniquePotentialWrongFreeStacks) {
				//write to a buffer so far how many times this potential leak
				StringBuffer wrongDeleteCandidateTimesFound = new StringBuffer();
				for (int k=0;k<i;k++) {
					//previous ones do not have it, as we search forward and when we find a match we remove it
					wrongDeleteCandidateTimesFound.append("{"+k+"}=0, ");
				}
				wrongDeleteCandidateTimesFound.append("{"+i+"}="+wrongDeleteCandidate.getTimesFound()+", ");
				
				//go through the rest of the files and check how many times it is there 
				for (int j=i+1; j<files.length;j++) {
					DTLeakAnalyzer otherTraceAnalysis = fileAnalysisResults.get(files[j]);
					boolean found = false;
					//for each potential leak in other files
					INNER_LOOP:
					for (int oplIndex=0;oplIndex<otherTraceAnalysis.uniquePotentialWrongFreeStacks.size();oplIndex++) {
						StackOccurence otherWrongDeleteCandidate = otherTraceAnalysis.uniquePotentialWrongFreeStacks.get(oplIndex);
						
						if (wrongDeleteCandidate.getStack().equals(otherWrongDeleteCandidate.getStack())) {
							//found match, the same stack
							found = true;
							wrongDeleteCandidateTimesFound.append("{"+j+"}="+otherWrongDeleteCandidate.getTimesFound()+", ");
							//remove from other list as not to process it again
							otherTraceAnalysis.uniquePotentialWrongFreeStacks.remove(oplIndex);
							break INNER_LOOP;
						}
					}
					if (!found) {
						wrongDeleteCandidateTimesFound.append("{"+j+"}=0, ");
					}
				}
				logMessage("Suspected wrong free stack found "+wrongDeleteCandidateTimesFound+" times",false, combinedFileWrite);
				logMessage(wrongDeleteCandidate.getStack()+"\n\n",false, combinedFileWrite);
				
			}			
		}
		
		DTLeakAnalyzer.logMessage("\n\n*** Strongly suspected wrong free cases (the suspected call stacks freed memory that was not allocated during the tracing and have not been found to correctly free memory during the tracing) ***\n\n", false, combinedFileWrite);
		//for each processed file
		for (int i=0;i<files.length;i++) {		
			DTLeakAnalyzer traceAnalysis = fileAnalysisResults.get(files[i]);
						
			//get all the potential leaks
			for (StackOccurence wrongDeleteCandidate: traceAnalysis.uniquePotentialWrongFreeStacksNeverCorrectlyFreed) {
				//write to a buffer so far how many times this potential leak
				StringBuffer wrongDeleteCandidateTimesFound = new StringBuffer();
				for (int k=0;k<i;k++) {
					//previous ones do not have it, as we search forward and when we find a match we remove it
					wrongDeleteCandidateTimesFound.append("{"+k+"}=0, ");
				}
				wrongDeleteCandidateTimesFound.append("{"+i+"}="+wrongDeleteCandidate.getTimesFound()+", ");
							
				//go through the rest of the files and check how many times it is there 
				for (int j=i+1; j<files.length;j++) {
					DTLeakAnalyzer otherTraceAnalysis = fileAnalysisResults.get(files[j]);
					boolean found = false;
					//for each potential leak in other files
					INNER_LOOP:
					for (int oplIndex=0;oplIndex<otherTraceAnalysis.uniquePotentialWrongFreeStacksNeverCorrectlyFreed.size();oplIndex++) {
						StackOccurence otherWrongDeleteCandidate = otherTraceAnalysis.uniquePotentialWrongFreeStacksNeverCorrectlyFreed.get(oplIndex);
						
						if (wrongDeleteCandidate.getStack().equals(otherWrongDeleteCandidate.getStack())) {
							//found match, the same stack
							found = true;
							wrongDeleteCandidateTimesFound.append("{"+j+"}="+otherWrongDeleteCandidate.getTimesFound()+", ");
							//remove from other list as not to process it again
							otherTraceAnalysis.uniquePotentialWrongFreeStacksNeverCorrectlyFreed.remove(oplIndex);
							break INNER_LOOP;
						}
					}
					if (!found) {
						wrongDeleteCandidateTimesFound.append("{"+j+"}=0, ");
					}
				}
				
				boolean foundSuccessfulFree = false;
				//now check all other files to see if this free stack has even correctly freed something
				LOOP2:
				for (int j=0; j<files.length;j++) {
					DTLeakAnalyzer otherTraceAnalysis = fileAnalysisResults.get(files[j]);					
					//now check if this free stack has succeeded in any other log file
					for (int oplIndex=0;oplIndex<otherTraceAnalysis.uniqueSuccessfulFreeStacks.size();oplIndex++) {
						MemoryAllocatorTraceEntry otherSuccesfullyDeletedStack = otherTraceAnalysis.uniqueSuccessfulFreeStacks.get(oplIndex);
						
						if (wrongDeleteCandidate.getStack().equals(otherSuccesfullyDeletedStack.getCallStack())) {
							//found match, the same stack
							foundSuccessfulFree = true;
							break LOOP2;
						}
					}
					
				}
				if (!foundSuccessfulFree) {
					logMessage("Very strongly suspected wrong free stack found "+wrongDeleteCandidateTimesFound+" times (it has never been found to correctly free memory for all trace files)\n",false, combinedFileWrite);
				} else {
					logMessage("Strongly suspected wrong free stack found "+wrongDeleteCandidateTimesFound+" times",false, combinedFileWrite);
					
				}
				logMessage(wrongDeleteCandidate.getStack()+"\n\n",false, combinedFileWrite);
				
			}			
		}
		
		DTLeakAnalyzer.logMessage("\n\n*** Suspected leaks (stacks that allocated memory that was not freed during the tracing)***\n\n", false, combinedFileWrite);
		Integer[] totalPendingAllocationsPerFile = new Integer[files.length];
		
		for (int i=0;i<totalPendingAllocationsPerFile.length;i++) {
			totalPendingAllocationsPerFile[i] = 0;
		}
		//for each processed file
		for (int i=0;i<files.length;i++) {		
			DTLeakAnalyzer traceAnalysis = fileAnalysisResults.get(files[i]);
						
			//get all the potential leaks
			for (StackOccurence leakCandidate: traceAnalysis.uniquePotentialLeakStacks) {
				//write to a buffer so far how many times this potential leak
				StringBuffer potentialLeakTimesFound = new StringBuffer();
				for (int k=0;k<i;k++) {
					//previous ones do not have it, as we search forward and when we find a match we remove it
					potentialLeakTimesFound.append("{"+k+"}=0, ");
				}
				potentialLeakTimesFound.append("{"+i+"}="+leakCandidate.getTimesFound()+", ");
				totalPendingAllocationsPerFile[i] += leakCandidate.getTimesFound();
				
				//go through the rest of the files and check how many times it is there 
				for (int j=i+1; j<files.length;j++) {
					DTLeakAnalyzer otherTraceAnalysis = fileAnalysisResults.get(files[j]);
					boolean found = false;
					//for each potential leak in other files
					INNER_LOOP:
					for (int oplIndex=0;oplIndex<otherTraceAnalysis.uniquePotentialLeakStacks.size();oplIndex++) {
						StackOccurence otherLeakCandidate = otherTraceAnalysis.uniquePotentialLeakStacks.get(oplIndex);
						
						if (leakCandidate.getStack().equals(otherLeakCandidate.getStack())) {
							//found match, the same stack
							found = true;
							potentialLeakTimesFound.append("{"+j+"}="+otherLeakCandidate.getTimesFound()+", ");
							totalPendingAllocationsPerFile[j] += otherLeakCandidate.getTimesFound();
							//remove from other list as not to process it again
							otherTraceAnalysis.uniquePotentialLeakStacks.remove(oplIndex);
							break INNER_LOOP;
						}
					}
					if (!found) {
						potentialLeakTimesFound.append("{"+j+"}=0, ");
					}
				}
				logMessage("Suspected leak stack found "+potentialLeakTimesFound+" times",false, combinedFileWrite);
				logMessage(leakCandidate.getStack()+"\n\n",false, combinedFileWrite);
				
			}			
		}		
		
		DTLeakAnalyzer.logMessage("\n\n*** Strongly suspected leaks (stacks that allocated memory that was not freed during the tracing and have not been found to allocate memory that was freed during the tracing )***\n\n", false, combinedFileWrite);
		//for each processed file
		for (int i=0;i<files.length;i++) {		
			DTLeakAnalyzer traceAnalysis = fileAnalysisResults.get(files[i]);
						
			//get all the potential leaks
			for (StackOccurence stronglySuspectedLeakCandidate: traceAnalysis.uniquePotentialLeakStacksNeverFreed) {
				//write to a buffer so far how many times this potential leak
				StringBuffer strongSuspectLeaktimesFound = new StringBuffer();
				for (int k=0;k<i;k++) {
					//previous ones do not have it, as we search forward and when we find a match we remove it
					strongSuspectLeaktimesFound.append("{"+k+"}=0, ");
				}
				strongSuspectLeaktimesFound.append("{"+i+"}="+stronglySuspectedLeakCandidate.getTimesFound()+", ");
				

				//go through the rest of the files and check how many times it is there 
				for (int j=i+1; j<files.length;j++) {
					DTLeakAnalyzer otherTraceAnalysis = fileAnalysisResults.get(files[j]);
					boolean found = false;
					//for each potential leak in other files
					INNER_LOOP:
					for (int oplIndex=0;oplIndex<otherTraceAnalysis.uniquePotentialLeakStacksNeverFreed.size();oplIndex++) {
						StackOccurence otherStronglySuspectedLeakCandidate = otherTraceAnalysis.uniquePotentialLeakStacksNeverFreed.get(oplIndex);
						
						if (stronglySuspectedLeakCandidate.getStack().equals(otherStronglySuspectedLeakCandidate.getStack())) {
							//found match, the same stack
							found = true;
							strongSuspectLeaktimesFound.append("{"+j+"}="+otherStronglySuspectedLeakCandidate.getTimesFound()+", ");
							//remove from other list as not to process it again
							otherTraceAnalysis.uniquePotentialLeakStacksNeverFreed.remove(oplIndex);
							break INNER_LOOP;
						}
					}
					if (!found) {
						strongSuspectLeaktimesFound.append("{"+j+"}=0, ");
					}
				}
				
				boolean foundSuccessfulStackDeallocation = false;
				LOOP2:
				for (int j=0; j<files.length;j++) {
					DTLeakAnalyzer otherTraceAnalysis = fileAnalysisResults.get(files[j]);

					//now check if this free stack has succeeded in any other log file
					for (int oplIndex=0;oplIndex<otherTraceAnalysis.uniqueSuccessfullyDeletedStacks.size();oplIndex++) {
						MemoryAllocatorTraceEntry otherSuccesfullyDeletedStack = otherTraceAnalysis.uniqueSuccessfullyDeletedStacks.get(oplIndex);
						
						if (stronglySuspectedLeakCandidate.getStack().equals(otherSuccesfullyDeletedStack.getCallStack())) {
							//found match, the same stack
							foundSuccessfulStackDeallocation = true;
							break LOOP2;
						}
					}
					
				}
				
				if (!foundSuccessfulStackDeallocation) {
					logMessage("Very strongly suspected leak stack found "+strongSuspectLeaktimesFound+" times (it has never allocated memory that has been deallocated for all trace files)\n",false, combinedFileWrite);
				} else {
					logMessage("Strongly suspected leak stack found "+strongSuspectLeaktimesFound+" times",false, combinedFileWrite);	
				}
				logMessage(stronglySuspectedLeakCandidate.getStack()+"\n\n",false, combinedFileWrite);
				
			}			
		}		
		
		StringBuffer totalPendingAllocationsPerFileSB = new StringBuffer();
		totalPendingAllocationsPerFileSB.append("\n\nTotal memory allocations that were not deleted per file :");
		for (int i=0;i<totalPendingAllocationsPerFile.length;i++) {
			totalPendingAllocationsPerFileSB.append("{"+i+"}="+totalPendingAllocationsPerFile[i]+" ");
		}
		
		logMessage(totalPendingAllocationsPerFileSB.toString(),false, combinedFileWrite);
		
		combinedFileWrite.close();
	}
		
	/**
	 * Prints a combined analysis results from a set of processed results files
	 * @param fileAnalysisResults the map with the files and their analysis results
	 * @param fileOut the output file to be used
	 * @throws UnsupportedEncodingException 
	 * @throws FileNotFoundException 
	 */
	public static void printProcessedFilesCombinedAnalysisResults(Map<File, DTLeakAnalyzer> fileAnalysisResults, String fileOut, boolean printAllocDeallocStacks) throws FileNotFoundException, UnsupportedEncodingException {
		PrintWriter combinedFileWrite = new PrintWriter(fileOut, "UTF-8");		
		
		File[] files = fileAnalysisResults.keySet().toArray(new File[]{});
		Arrays.sort(files, new Comparator<File>() {
			@Override
			public int compare(File o1, File o2) {
				return o1.getName().compareTo(o2.getName());
			}
			
		});
		
		StringBuffer fileNamesSb = new StringBuffer();
		for (int i=0;i<files.length;i++) {	
			fileNamesSb.append(files[i].getName()+" {"+i+"}");
			fileNamesSb.append("\n");
		}
		fileNamesSb.append("\n");
		DTLeakAnalyzer.logMessage("Combined (short and long term) memory allocator analysis for files:\n"+fileNamesSb, false, combinedFileWrite);

		//ALLOCATION STACKS
		if (printAllocDeallocStacks) {
			DTLeakAnalyzer.logMessage("\n\n*** Allocation Stacks ***\n\n", false, combinedFileWrite);
		}
		
		Integer[] totalAllocationsPerFile = new Integer[files.length];
		for (int i=0;i<totalAllocationsPerFile.length;i++) {
			totalAllocationsPerFile[i] = 0;
		}		
		//for each processed file
		for (int i=0;i<files.length;i++) {		
			DTLeakAnalyzer traceAnalysis = fileAnalysisResults.get(files[i]);
						
			//get all the allocation stacks
			for (StackOccurence allocationStack: traceAnalysis.uniqueAllocationStacks) {
				//write to a buffer so far how many times this potential leak
				StringBuffer allocationStacksTimesFound = new StringBuffer();
				for (int k=0;k<i;k++) {
					//previous ones do not have it, as we search forward and when we find a match we remove it
					allocationStacksTimesFound.append("{"+k+"}=0, ");
				}
				allocationStacksTimesFound.append("{"+i+"}="+allocationStack.getTimesFound()+", ");
				totalAllocationsPerFile[i] += allocationStack.getTimesFound();
				
				//go through the rest of the files and check how many times it is there 
				for (int j=i+1; j<files.length;j++) {
					DTLeakAnalyzer otherTraceAnalysis = fileAnalysisResults.get(files[j]);
					boolean found = false;
					//for each potential leak in other files
					INNER_LOOP:
					for (int oplIndex=0;oplIndex<otherTraceAnalysis.uniqueAllocationStacks.size();oplIndex++) {
						StackOccurence otherAllocationStack = otherTraceAnalysis.uniqueAllocationStacks.get(oplIndex);
						
						if (allocationStack.getStack().equals(otherAllocationStack.getStack())) {
							//found match, the same stack
							found = true;
							allocationStacksTimesFound.append("{"+j+"}="+otherAllocationStack.getTimesFound()+", ");
							totalAllocationsPerFile[j] += otherAllocationStack.getTimesFound();
							//remove from other list as not to process it again
							otherTraceAnalysis.uniqueAllocationStacks.remove(oplIndex);
							break INNER_LOOP;
						}
					}
					if (!found) {
						allocationStacksTimesFound.append("{"+j+"}=0, ");
					}
				}
				if (printAllocDeallocStacks) {
					logMessage("Allocation stack found "+allocationStacksTimesFound+" times",false, combinedFileWrite);
					logMessage(allocationStack.getStack()+"\n\n",false, combinedFileWrite);
				}
				
			}			
		}
		
		
		//Suspect Memory leaks
		DTLeakAnalyzer.logMessage("\n\n*** Suspect memory leak stacks (such memory allocations have never been found to be freed in the short term traces) ***\n\n", false, combinedFileWrite);

		//for each processed file
		for (int i=0;i<files.length;i++) {		
			DTLeakAnalyzer traceAnalysis = fileAnalysisResults.get(files[i]);
						
			//get all the allocation stacks
			for (StackOccurence allocationStack: traceAnalysis.uniqueUnfreedAllocationStacks) {
				//write to a buffer so far how many times this potential leak
				StringBuffer allocationStacksTimesFound = new StringBuffer();
				for (int k=0;k<i;k++) {
					//previous ones do not have it, as we search forward and when we find a match we remove it
					allocationStacksTimesFound.append("{"+k+"}=0, ");
				}
				allocationStacksTimesFound.append("{"+i+"}="+allocationStack.getTimesFound()+", ");
				
				//go through the rest of the files and check how many times it is there 
				for (int j=i+1; j<files.length;j++) {
					DTLeakAnalyzer otherTraceAnalysis = fileAnalysisResults.get(files[j]);
					boolean found = false;
					//for each potential leak in other files
					INNER_LOOP:
					for (int oplIndex=0;oplIndex<otherTraceAnalysis.uniqueUnfreedAllocationStacks.size();oplIndex++) {
						StackOccurence otherAllocationStack = otherTraceAnalysis.uniqueUnfreedAllocationStacks.get(oplIndex);
						
						if (allocationStack.getStack().equals(otherAllocationStack.getStack())) {
							//found match, the same stack
							found = true;
							allocationStacksTimesFound.append("{"+j+"}="+otherAllocationStack.getTimesFound()+", ");
							//remove from other list as not to process it again
							otherTraceAnalysis.uniqueUnfreedAllocationStacks.remove(oplIndex);
							break INNER_LOOP;
						}
					}
					if (!found) {
						allocationStacksTimesFound.append("{"+j+"}=0, ");
					}
				}
				logMessage("Suspect allocation stack found "+allocationStacksTimesFound+" times",false, combinedFileWrite);
				logMessage(allocationStack.getStack()+"\n\n",false, combinedFileWrite);
				
			}			
		}				
		
		if (printAllocDeallocStacks) {
			//DEALLOCATION STACKS
			DTLeakAnalyzer.logMessage("\n\n*** Dellocation Stacks ***\n\n", false, combinedFileWrite);
		}
		Integer[] totalDeallocationsPerFile = new Integer[files.length];			
		for (int i=0;i<totalDeallocationsPerFile.length;i++) {
			totalDeallocationsPerFile[i] = 0;
		}		
		
		//for each processed file
		for (int i=0;i<files.length;i++) {		
			DTLeakAnalyzer traceAnalysis = fileAnalysisResults.get(files[i]);
						
			//get all the allocation stacks
			for (StackOccurence deallocationStack: traceAnalysis.uniqueDeallocationStacks) {
				//write to a buffer so far how many times this potential leak
				StringBuffer deallocationStacksTimesFound = new StringBuffer();
				for (int k=0;k<i;k++) {
					//previous ones do not have it, as we search forward and when we find a match we remove it
					deallocationStacksTimesFound.append("{"+k+"}=0, ");
				}
				deallocationStacksTimesFound.append("{"+i+"}="+deallocationStack.getTimesFound()+", ");
				totalDeallocationsPerFile[i] += deallocationStack.getTimesFound();
				
				//go through the rest of the files and check how many times it is there 
				for (int j=i+1; j<files.length;j++) {
					DTLeakAnalyzer otherTraceAnalysis = fileAnalysisResults.get(files[j]);
					boolean found = false;
					//for each potential leak in other files
					INNER_LOOP:
					for (int oplIndex=0;oplIndex<otherTraceAnalysis.uniqueDeallocationStacks.size();oplIndex++) {
						StackOccurence otherDeallocationStack = otherTraceAnalysis.uniqueDeallocationStacks.get(oplIndex);
						
						if (deallocationStack.getStack().equals(otherDeallocationStack.getStack())) {
							//found match, the same stack
							found = true;
							deallocationStacksTimesFound.append("{"+j+"}="+otherDeallocationStack.getTimesFound()+", ");
							totalDeallocationsPerFile[j] += otherDeallocationStack.getTimesFound();
							//remove from other list as not to process it again
							otherTraceAnalysis.uniqueDeallocationStacks.remove(oplIndex);
							break INNER_LOOP;
						}
					}
					if (!found) {
						deallocationStacksTimesFound.append("{"+j+"}=0, ");
					}
				}
				if (printAllocDeallocStacks) {
					logMessage("Deallocation stack found "+deallocationStacksTimesFound+" times",false, combinedFileWrite);
					logMessage(deallocationStack.getStack()+"\n\n",false, combinedFileWrite);
				}
				
			}			
		}			
		
		//DEALLOCATION STACKS
		DTLeakAnalyzer.logMessage("\n\n*** Unknown free stacks (may potentially free memory from the suspect memory leaks reported here) ***\n\n", false, combinedFileWrite);
		
		
		//for each processed file
		for (int i=0;i<files.length;i++) {		
			DTLeakAnalyzer traceAnalysis = fileAnalysisResults.get(files[i]);
						
			//get all the allocation stacks
			for (StackOccurence deallocationStack: traceAnalysis.uniqueUnknownDeallocationStacks) {
				//write to a buffer so far how many times this potential leak
				StringBuffer deallocationStacksTimesFound = new StringBuffer();
				for (int k=0;k<i;k++) {
					//previous ones do not have it, as we search forward and when we find a match we remove it
					deallocationStacksTimesFound.append("{"+k+"}=0, ");
				}
				deallocationStacksTimesFound.append("{"+i+"}="+deallocationStack.getTimesFound()+", ");
				
				//go through the rest of the files and check how many times it is there 
				for (int j=i+1; j<files.length;j++) {
					DTLeakAnalyzer otherTraceAnalysis = fileAnalysisResults.get(files[j]);
					boolean found = false;
					//for each potential leak in other files
					INNER_LOOP:
					for (int oplIndex=0;oplIndex<otherTraceAnalysis.uniqueUnknownDeallocationStacks.size();oplIndex++) {
						StackOccurence otherDeallocationStack = otherTraceAnalysis.uniqueUnknownDeallocationStacks.get(oplIndex);
						
						if (deallocationStack.getStack().equals(otherDeallocationStack.getStack())) {
							//found match, the same stack
							found = true;
							deallocationStacksTimesFound.append("{"+j+"}="+otherDeallocationStack.getTimesFound()+", ");
							//remove from other list as not to process it again
							otherTraceAnalysis.uniqueUnknownDeallocationStacks.remove(oplIndex);
							break INNER_LOOP;
						}
					}
					if (!found) {
						deallocationStacksTimesFound.append("{"+j+"}=0, ");
					}
				}
				logMessage("Unknown Deallocation stack found "+deallocationStacksTimesFound+" times",false, combinedFileWrite);
				logMessage(deallocationStack.getStack()+"\n\n",false, combinedFileWrite);
				
			}			
		}						
		
		StringBuffer totalAllocDeallocDiffPerFile = new StringBuffer();
		totalAllocDeallocDiffPerFile.append("\n\nMemory allocations - memory deallocations per file :");
		for (int i=0;i<totalDeallocationsPerFile.length;i++) {
			totalAllocDeallocDiffPerFile.append("{"+i+"}="+(totalAllocationsPerFile[i]-totalDeallocationsPerFile[i])+" ");
		}
		
		logMessage(totalAllocDeallocDiffPerFile.toString(),false, combinedFileWrite);
		
		combinedFileWrite.close();
	}
	
	

	/**
	 * Log entry class
	 * holds information about the log entry for a generic
	 * 
	 * @author Petros Pissias
	 *
	 */
	public static class MemoryAllocatorTraceEntry {
		private final long entryNumber;
		private final String date;
		private final MemoryAllocationTraceEntryType type;
		private final String threadId; 
		private final String address;
		private final long size;
		private final String previousAddress;
		private final String callStack; 
		
		public MemoryAllocatorTraceEntry(List<String> lines) throws IOException {
			if (lines.size() == 0) {
				throw new IOException("Empty trace entry requested");
			} else {
				String firstLine = lines.get(0).replaceAll("<__", "").replaceAll("__>", "");
				String[] lineFields = firstLine.split(";");
				
				if (lineFields.length < 5) {
					throw new IOException("cannot decode line:"+firstLine);
				}
				
				//determine log type
				if (lineFields[3].equals("malloc")) {
					type = MemoryAllocationTraceEntryType.MALLOC;
				} else if (lineFields[3].equals("calloc")) {
					type = MemoryAllocationTraceEntryType.CALLOC;
				} else if (lineFields[3].equals("free")) {
					type = MemoryAllocationTraceEntryType.FREE;
				} else if (lineFields[3].equals("realloc")) {
					type = MemoryAllocationTraceEntryType.REALLOC;
				} else {
					//do not understand
					throw new IOException("cannot decode line:"+firstLine);
				}
				
				//get data
				entryNumber = Long.parseLong(lineFields[0]);
				date = lineFields[1];
				threadId = lineFields[2];
				
				//now special handling
				switch (type) {
				case MALLOC : {
					address = lineFields[4];
					size = Long.parseLong(lineFields[5]);
					previousAddress = null;
					break;
				}
				
				case CALLOC : {
					address = lineFields[4];
					size = Long.parseLong(lineFields[5]);
					previousAddress = null;			
					break;
				}
				
				case REALLOC : {
					address = lineFields[5];
					size = Long.parseLong(lineFields[6]);
					previousAddress = lineFields[4];		
					break;
				}
				
				case FREE : {
					address = lineFields[4];
					size=0;
					previousAddress = null;	
					break;
				}
				
				default : {
					throw new IOException("cannot determine type:"+type.name());
				}
				}
				
				//get call stack
				StringBuffer sb = new StringBuffer();
				for (int i=1;i<lines.size();i++) {
					String trimmedLine = lines.get(i).replaceAll("<__", "").replaceAll("__>", "").trim();
					if (!trimmedLine.equals("")) {
						sb.append(trimmedLine).append("\n");
					}
				}
				if (sb.toString().isEmpty()) {
					callStack = null;
				} else {
					callStack = clearTopLevelStackReturnPointer(sb.toString());
				}
				
			}
		}

		public long getEntryNumber() {
			return entryNumber;
		}

		public String getDate() {
			return date;
		}

		public MemoryAllocationTraceEntryType getType() {
			return type;
		}

		public String getThreadId() {
			return threadId;
		}

		public String getAddress() {
			return address;
		}

		public long getSize() {
			return size;
		}

		public String getPreviousAddress() {
			return previousAddress;
		}

		public String getCallStack() {
			return callStack;
		}

		@Override
		public String toString() {
			return "DTGenericLeakLogEntry [entryNumber=" + entryNumber
					+ ", date=" + date + ", type=" + type + ", threadId="
					+ threadId + ", address=" + address + ", size=" + size
					+ ", previousAddress=" + previousAddress + ", callStack="
					+ callStack + "]";
		}

		
	}	

	/**
	 * Log entry class
	 * holds information about the log entry for a generic
	 * 
	 * @author Petros Pissias
	 *
	 */
	public static class BrkTraceEntry {
		private final long entryNumber;
		private final String date;
		private final BrkTraceEntryType type;
		private final String threadId; 
		private final String address;
		private final long size;
		private final boolean success; 
		private final String callStack; 
		
		public BrkTraceEntry(List<String> lines) throws IOException {
			if (lines.size() == 0) {
				throw new IOException("Empty trace entry requested");
			} else {
				String firstLine = lines.get(0).replaceAll("<__", "").replaceAll("__>", "");
				String[] lineFields = firstLine.split(";");
				
				if (lineFields.length < 6) {
					throw new IOException("cannot decode line:"+firstLine);
				}
				
				//determine log type
				if (lineFields[3].equals("brk")) {
					type = BrkTraceEntryType.BRK;
				} else if (lineFields[3].equals("sbrk")) {
					type = BrkTraceEntryType.SBRK;
				} else {
					//do not understand
					throw new IOException("cannot decode line:"+firstLine);
				}
				
				//get data
				entryNumber = Long.parseLong(lineFields[0]);
				date = lineFields[1];
				threadId = lineFields[2];
				
				//now special handling
				switch (type) {
				case BRK : {
					address = lineFields[4];
					size = -1;
					int brkReturn = Integer.parseInt(lineFields[5]);
					if (brkReturn != -1) {
						//success
						success = true;
					} else {
						success = false;
					}

					break;
				}
				
				case SBRK : {
					address = lineFields[4];
					size = Long.parseLong(lineFields[5]);
					
					if (!address.equals("-0x1")) {
						//success
						success = true;
					} else {
						success = false;
					}					
					break;
				}
				
				default : {
					throw new IOException("cannot determine type:"+type.name());
				}
				}
				
				//get call stack
				StringBuffer sb = new StringBuffer();
				for (int i=1;i<lines.size();i++) {
					String trimmedLine = lines.get(i).replaceAll("<__", "").replaceAll("__>", "").trim();
					if (!trimmedLine.equals("")) {
						sb.append(trimmedLine).append("\n");
					}
				}
				if (sb.toString().isEmpty()) {
					callStack = null;
				} else {
					callStack = clearTopLevelStackReturnPointer(sb.toString());
				}
				
			}
		}

		public long getEntryNumber() {
			return entryNumber;
		}

		public String getDate() {
			return date;
		}

		public BrkTraceEntryType getType() {
			return type;
		}

		public String getThreadId() {
			return threadId;
		}

		public String getAddress() {
			return address;
		}

		public long getSize() {
			return size;
		}

		public boolean isSuccess() {
			return success;
		}

		public String getCallStack() {
			return callStack;
		}

		@Override
		public String toString() {
			return "DTLeakBrkLogEntry [entryNumber=" + entryNumber + ", date="
					+ date + ", type=" + type + ", threadId=" + threadId
					+ ", address=" + address + ", size=" + size + ", success="
					+ success + ", callStack=" + callStack + "]";
		}
		
		
	}
		
	/**
	 * Class that holds informatoin about how many times 
	 * a specific call stack allocated memory that was not deleted
	 * 
	 * @author Petros Pissias
	 *
	 */
	public static class StackOccurence {
		private final String stack;
		private volatile int timesFound;
		
		public StackOccurence(String stack, int times) {
			this.stack = stack;
			this.timesFound = times;
		}

		public StackOccurence(String stack) {
			this.stack = stack;
			this.timesFound = 1;
		}
		
		public String getStack() {
			return stack;
		}

		public int getTimesFound() {
			return timesFound;
		}

		public void increaseTimesFound() {
			timesFound++;
		}
		
		public void increaseTimesFound(int amount) {
			timesFound+=amount;;
		}		
		public String getInformation() {
			return "Found "+timesFound+" times";
		}
	}
	
	/**
	 * Class that holds informatoin about how many times 
	 * a specific call stack allocated memory that was not deleted
	 * 
	 * @author Petros Pissias
	 *
	 */
	public static class BrkStackOccurence extends StackOccurence{
		private volatile long sizeIncrease;
		
		public BrkStackOccurence(String stack, int times, long sizeIncrease) {
			super(stack, times);
			this.sizeIncrease = sizeIncrease;
		}

		public BrkStackOccurence(String stack, long sizeIncrease) {
			super(stack);
			this.sizeIncrease = sizeIncrease;
		}
		
		public long getSizeIncrease() {
			return sizeIncrease;
		}
		
		public void increaseSize(long size) {
			sizeIncrease+=size;
		}		
		
		public String getInformation() {
			return super.getInformation()+", overall size increase: "+sizeIncrease+" bytes";
		}		
	}
		
	
	public static enum MemoryAllocationTraceEntryType {
		MALLOC,
		CALLOC,
		REALLOC,
		FREE
	}
	
	public static enum BrkTraceEntryType {
		BRK,
		SBRK,
	}
	
	public static enum TraceFileType {
		MEMALLOC,
		BRK
	}
	
}
