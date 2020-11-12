package main

import (
	"io/ioutil"
	"os"
	"strings"
)

func main() {

	border := "// ----------------------------------------------------------------------------"
	content, _ := ioutil.ReadFile("httplib.h")
	lines := strings.Split(string(content), "\n")
	inImplementation := false

	os.Create("out")

	fh, _ := os.Create("out/httplib.h")
	fc, _ := os.Create("out/httplib.cc")

	fc.WriteString("#include \"httplib.h\"\n")
	fc.WriteString("namespace httplib {\n")

	for _, line := range lines {
		isBorderLine := strings.Contains(line, border)
		if isBorderLine {
			if true == inImplementation {
				inImplementation = false
			} else {
				inImplementation = true
			}
		} else {
			if inImplementation {
				toWrite := strings.ReplaceAll(line, "inline ", "")
				fc.WriteString(toWrite)
			} else {
				fh.WriteString(line)
			}
		}
	}

	fc.WriteString("} // namespace httplib\n")

}
