source := $(wildcard src/*.java)
libs := $(wildcard lib/*.jar)

Client: compile
	java -cp bin Client

Server: compile
	java -cp bin Server

doc:
	javadoc -d docs -cp docs:lib/*.jar src/*.java

compile: $(source)
	javac -d bin -cp lib/bcutil-jdk15to18-176.jar:lib/bcprov-debug-jdk15to18-176.jar:lib/bcpkix-jdk15to18-176.jar:lib/junit-4.13.2.jar:lib/junit-jupiter-api-5.9.0.jar src/*.java

clean:
	rm -r docs/* bin/*.class
