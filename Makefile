PROJECT = src/Project1_Omega.csproj
CONFIGURATION = Release
RUNTIME = linux-x64
OUTPUT_DIR = publish

all: clean publish

publish:
	dotnet publish $(PROJECT) -r $(RUNTIME) -c $(CONFIGURATION) -o $(OUTPUT_DIR) --self-contained true
clean:
	rm -rf src/bin
	rm -rf src/obj
	rm -rf $(OUTPUT_DIR)
