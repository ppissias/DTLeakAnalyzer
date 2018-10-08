import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Tool for analzing logs produced with dtrace under Solaris in support of 
 * memory leak investigations.
 * 
 * @author Petros Pissias
 *
 */
public class DTLeakAnalyzer {

	//this file contains the traces
	private final String inFile; 
	
	//this file eill contian the analysis of the traces
	private final String outFile;
	
	//start / end trace sequences
	private final String entryStartCharSequence = "<__";
	private final String entryEndCharSequence = "__>";
	
	/**
	 * new instance of the analyzer 
	 * @param inFile the traces
	 * @param outFile the output analysis of the traces that will be produced 
	 * @throws Exception in case the traces cannot be parsed or the files cannot be accessed
	 */
	public DTLeakAnalyzer(String inFile, String outFile) {
		this.inFile = inFile;
		this.outFile = outFile;
	}
	
	/**
	 * Performs the traces analysis
	 * @throws IOException 
	 */
	public void performAnalysis() throws IOException {
		//open output file
		PrintWriter writer = new PrintWriter(outFile, "UTF-8");
		
		logMessage("Trace analyser started on "+new Date(), writer, true);
				
		//map to keep track of memory allocations
		Map<String, DTLeakLogEntry> memoryAllocation = new HashMap<String, DTLeakLogEntry>();
		
		//map to save new[] and delete[] operations to detect issues with new and delete
		Map<String, DTLeakLogEntry> memoryArrayAllocation = new HashMap<String, DTLeakLogEntry>();
		
		//keep the previous entry to associate new[] calls. Keep the last entry per thread
		Map<String,DTLeakLogEntry> previousEntries = new HashMap<String,DTLeakLogEntry>();
		
		//array to keep detected wrong deletes
		List<DTLeakWrongDeleteEntry> wrongDeletes = new ArrayList<DTLeakWrongDeleteEntry>();
		
		//open the traces file and process each line 
		try (BufferedReader br = new BufferedReader(new FileReader(inFile))) {
			
			//read all entries
			DTLeakLogEntry traceEntry = null;			
			while ((traceEntry = readTraceEntry(br)) != null) {
				
				//first do some consistency checks
				if (previousEntries.get(traceEntry.getThreadId()) != null)  {
					if (previousEntries.get(traceEntry.getThreadId()).getType().equals(DTLeakLogEntryType.NEWARRAY)){ 
						if (!traceEntry.getType().equals(DTLeakLogEntryType.NEW)) {
							logMessage("Previous entry was new[] but this one is not new\n previous:"+previousEntries.get(traceEntry.getThreadId())+"\n\ncurrent:"+traceEntry, writer, true);
							throw new IOException("Error: Previous entry was new[] but this one is not new. See log file for more information");						
						}
					}
					
					if (previousEntries.get(traceEntry.getThreadId()).getType().equals(DTLeakLogEntryType.DELETEARRAY)){ 
						if (!traceEntry.getType().equals(DTLeakLogEntryType.DELETE)) {
							logMessage("Previous entry was delete[] but this one is not delete\n previous:"+previousEntries.get(traceEntry.getThreadId())+"\n\ncurrent:"+traceEntry, writer, true);
							throw new IOException("Error: Previous entry was delete[] but this one is not delete. See log file for more information");						
						}					
					}
				}
				//now process the entry
				if (traceEntry.getType().equals(DTLeakLogEntryType.NEW)) {
					//sanity check
					if (memoryAllocation.containsKey(traceEntry.getAddress())) {
						//this should not happen.
						logMessage("Found allocation on memory address:"+traceEntry.getAddress()+" that was already allocated by: "+memoryAllocation.get(traceEntry.getAddress()), writer, true);
						throw new IOException("Error: memory allocation in allocated memory. Corrupted trace file. See log file for more information");
					}
					
					//add to map
					memoryAllocation.put(traceEntry.getAddress(), traceEntry);
					if (previousEntries.get(traceEntry.getThreadId()) != null) {
						//check if this was a new[] call
						if (previousEntries.get(traceEntry.getThreadId()).getType().equals(DTLeakLogEntryType.NEWARRAY)){ 
							//add to list
							memoryArrayAllocation.put(traceEntry.getAddress(), traceEntry);
						}
					}
				} else if (traceEntry.getType().equals(DTLeakLogEntryType.DELETE)) {
					//check if it exists already on the map
					if (memoryAllocation.containsKey(traceEntry.getAddress())) {
						//as expected, we had an allocation and this is the de-allocation
						memoryAllocation.remove(traceEntry.getAddress());						
					} else {
						//not expected, but can happen since we are not monitoring all allocation from the beginning of the execution
						logMessage("Info: found deallocation from unallocated memory:"+traceEntry.getAddress(), writer, false);
					}
					if (memoryArrayAllocation.containsKey(traceEntry.getAddress())) {
						//logMessage("Error: found delete for memory that was allocated with new[]\n:"+traceEntry+"\n", writer, false);
						//remove so that we do not detect it again and again
						DTLeakLogEntry arrayAllocationEntry = memoryArrayAllocation.remove(traceEntry.getAddress());
						
						//store this error
						wrongDeletes.add(new DTLeakWrongDeleteEntry(traceEntry, arrayAllocationEntry));
					}
				} else if (traceEntry.getType().equals(DTLeakLogEntryType.NEWARRAY)) {
					//found new[] entry
					//no need to do something at this point, it will be checked on the next entry which will be a new operation
				} else if (traceEntry.getType().equals(DTLeakLogEntryType.DELETEARRAY)) {
					if (!memoryArrayAllocation.containsKey(traceEntry.getAddress())) {
						logMessage("Info: found array deallocation from unallocated memory:"+traceEntry.getAddress(), writer, false);						
					} else {
						//remove
						memoryArrayAllocation.remove(traceEntry.getAddress());
					}
				} else {
				}
				
				//save entry to associate on new[] operations
				previousEntries.put(traceEntry.getThreadId(), traceEntry);
			}
			
			logMessage("\n\nProcessing wrong deletes [delete on memory that was allocated with new[]), found "+wrongDeletes.size()+" instances", writer, true);
			
			//find unique cases and store them
			List<DTLeakWrongDeleteReportEntry> uniqueWrongDeleteStacks = new ArrayList<DTLeakWrongDeleteReportEntry>();
			for (DTLeakWrongDeleteEntry entry : wrongDeletes) {
				boolean found = false;
				for (DTLeakWrongDeleteReportEntry reportEntry : uniqueWrongDeleteStacks) {
					if (reportEntry.getStack().equals(entry.getDeleteLogEntry().getCallStack())) {
						found = true;
						//increase counter
						reportEntry.increaseTimesFound();						
						break;
					}
				}
				if (!found) {
					uniqueWrongDeleteStacks.add(new DTLeakWrongDeleteReportEntry(entry.getDeleteLogEntry().getCallStack(), 1, entry));
				} 
			}
			
			logMessage("found "+uniqueWrongDeleteStacks.size()+" unique wrong delete stacks", writer, true);
			
			//sort list according to times found
			Collections.sort(uniqueWrongDeleteStacks, new Comparator<DTLeakWrongDeleteReportEntry> () {
				@Override
				public int compare(DTLeakWrongDeleteReportEntry o1,
						DTLeakWrongDeleteReportEntry o2) {
					return o2.getTimesFound()-o1.getTimesFound();
				}				
			});
			
			for (DTLeakWrongDeleteReportEntry wrongDeleteStack : uniqueWrongDeleteStacks) {
				logMessage("Found wrong delete stack "+wrongDeleteStack.getTimesFound()+" times. Stack:\n"+wrongDeleteStack.getStack(), writer, false);
				logMessage("Example of this allocation. Allocation stack:\n\n"+wrongDeleteStack.getExample().getArrayAllocationLogEntry()+"\n\n", writer, false);
			}
			
			logMessage("Analyzing "+memoryAllocation.keySet().size()+" potential memory leaks", writer, true);
			
			//second step, analyze non empty memory allocations on the map to find unique call stacks
			List<DTLeakReportEntry> uniquePotentialLeakStacks = new ArrayList<DTLeakReportEntry>();
			for (String memoryAddress : memoryAllocation.keySet()) {
				DTLeakLogEntry unallocatedMemoryCallStack = memoryAllocation.get(memoryAddress);
				boolean found = false;
				for (DTLeakReportEntry uniquePLeak :uniquePotentialLeakStacks) {
					if (uniquePLeak.getStack().equals(unallocatedMemoryCallStack.getCallStack())) {
						found = true;
						uniquePLeak.increaseTimesFound();
						break;
					}
				}
				if (!found) {
					//insert for the first time
					uniquePotentialLeakStacks.add(new DTLeakReportEntry(unallocatedMemoryCallStack.getCallStack(), 1));
				}
			}
			
			//sort
			Collections.sort(uniquePotentialLeakStacks, new Comparator<DTLeakReportEntry>() {

				@Override
				public int compare(DTLeakReportEntry o1, DTLeakReportEntry o2) {					
					return o2.getTimesFound() - o1.getTimesFound();
				}
				
			});
			


			logMessage("Processing completed.\nDetected "+uniquePotentialLeakStacks.size()+" potential memory leaks\n", writer, true);


			for (DTLeakReportEntry suspectCallStack : uniquePotentialLeakStacks) {
				logMessage("Suspect leak stack found "+suspectCallStack.getTimesFound()+" times",writer, false);
				logMessage(suspectCallStack.getStack()+"\n\n",writer, false);
			}

			//now check to see
			logMessage("finished on "+new Date(), writer, true);
			
		}catch (IOException e) {
			System.out.println("problem reading input (traces) file:"+e.getMessage());
			
			throw e;
		} finally {
			writer.close();
		}
	}


	/**
	 * logs a message to the log file and system out of the passed parameter is true
	 * @param writer
	 * @param systemOut
	 */
	private void logMessage(String message, PrintWriter writer, boolean systemOut) {
		writer.println(message);
		if (systemOut) {
			System.out.println(message);
		}
	}
	/**
	 * reads the next log entry from the file
	 * @param br
	 * @return
	 * @throws IOException
	 */
	public DTLeakLogEntry readTraceEntry(BufferedReader br) throws IOException{
		
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
						return new DTLeakLogEntry(entryLines);
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
					return new DTLeakLogEntry(entryLines);
				}
			}
											
		}
		//reached end of file
		return null;
	}

	
	
	/**
	 * Entry point to start the analysis tool
	 * @param args arguments: <input file> <output file>
	 */
	public static void main(String[] args) throws IOException{

		if (args.length != 2) {
			System.out.println("arguments: <input file> <output file>" );
			return;
		}
		
		DTLeakAnalyzer dtLeakAnalyzer = new DTLeakAnalyzer(args[0], args[1]);
		dtLeakAnalyzer.performAnalysis();
	}
	
	/**
	 * Log entry class
	 * holds information about the log entry 
	 * 
	 * @author Petros Pissias
	 *
	 */
	public class DTLeakLogEntry {
		private final long entryNumber;
		private final String date;
		private final DTLeakLogEntryType type;
		private final String threadId; 
		private final String address; 
		private final String additionalInfo;
		private final String callStack; 
		
		public DTLeakLogEntry(List<String> lines) throws IOException {
			if (lines.size() == 0) {
				throw new IOException("Empty trace entry requested");
			} else {
				String firstLine = lines.get(0).replaceAll("<__", "").replaceAll("__>", "");
				String[] lineFields = firstLine.split(";");
				
				if (lineFields.length < 5) {
					throw new IOException("cannot decode line:"+firstLine);
				}
				
				//determine log type
				if (lineFields[3].equals("new") || lineFields[3].equals("malloc")) {
					type = DTLeakLogEntryType.NEW;
				} else if (lineFields[3].equals("new[]")) {
					type = DTLeakLogEntryType.NEWARRAY;
				} else if (lineFields[3].equals("delete") || lineFields[3].equals("free")) {
					type = DTLeakLogEntryType.DELETE;
				} else if (lineFields[3].equals("delete[]")) {
					type = DTLeakLogEntryType.DELETEARRAY;
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
				case DELETE : {
					address = lineFields[4];
					additionalInfo = null;
					break;
				}
				
				case DELETEARRAY : {
					address = lineFields[4];
					additionalInfo = null;					
					break;
				}
				
				case NEW : {
					address = lineFields[4];
					additionalInfo = lineFields[5];			
					break;
				}
				
				case NEWARRAY : {
					address = null;
					additionalInfo = lineFields[5];
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
					callStack = sb.toString();
				}
				
			}
		}

		public long getEntryNumber() {
			return entryNumber;
		}

		public String getDate() {
			return date;
		}

		public DTLeakLogEntryType getType() {
			return type;
		}

		public String getThreadId() {
			return threadId;
		}

		public String getAddress() {
			return address;
		}

		public String getAdditionalInfo() {
			return additionalInfo;
		}

		public String getCallStack() {
			return callStack;
		}

		@Override
		public String toString() {
			return "DTLeakLogEntry [entryNumber=" + entryNumber + ", date="
					+ date + ", type=" + type + ", threadId=" + threadId
					+ ", address=" + address + ", additionalInfo="
					+ additionalInfo + ", callStack=" + callStack + "]";
		}
		
		
	}

	/**
	 * Class that holds informatoin about how many times 
	 * a specific call stack allocated memory that was not deleted
	 * 
	 * @author Petros Pissias
	 *
	 */
	public class DTLeakReportEntry {
		private final String stack;
		private volatile int timesFound;
		
		public DTLeakReportEntry(String stack, int times) {
			this.stack = stack;
			this.timesFound = times;
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
		
	}
	
	/**
	 * Class that holds information about the wrong delete entries
	 * @author Petros Pissias
	 *
	 */
	public class DTLeakWrongDeleteEntry {
		private final DTLeakLogEntry deleteLogEntry; 
		private final DTLeakLogEntry arrayAllocationLogEntry;
		public DTLeakWrongDeleteEntry(DTLeakLogEntry deleteLogEntry,
				DTLeakLogEntry arrayAllocationLogEntry) {
			super();
			this.deleteLogEntry = deleteLogEntry;
			this.arrayAllocationLogEntry = arrayAllocationLogEntry;
		}
		public DTLeakLogEntry getDeleteLogEntry() {
			return deleteLogEntry;
		}
		public DTLeakLogEntry getArrayAllocationLogEntry() {
			return arrayAllocationLogEntry;
		}		
	}
	
	
	/**
	 * Class that holds informatoin about how many times 
	 * a specific wrong delete was performed
	 * 
	 * @author Petros Pissias
	 *
	 */
	public class DTLeakWrongDeleteReportEntry {
		
		private final String stack;
		private volatile int timesFound;
		private final DTLeakWrongDeleteEntry example;
		
		public DTLeakWrongDeleteReportEntry(String stack, int times, DTLeakWrongDeleteEntry example) {
			this.stack = stack;
			this.timesFound = times;
			this.example = example;
		}

		public String getStack() {
			return stack;
		}

		public int getTimesFound() {
			return timesFound;
		}

		public DTLeakWrongDeleteEntry getExample() {
			return example;
		}	

		public void increaseTimesFound() {
			timesFound++;
		}
		
	}	
	
	public enum DTLeakLogEntryType {
		NEW,
		NEWARRAY,
		DELETE,
		DELETEARRAY
	}
}
