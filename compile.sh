javac -d classes src/DTLeakAnalyzer.java
jar cvfm dtleakanalyzer.jar resources/manifest.txt -C classes .