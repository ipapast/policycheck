package main

import (
	"reflect"
	"testing"
)

func violationIDs(vs []violation) []string {
	ids := []string{}
	for _, v := range vs {
		ids = append(ids, v.ID)
	}
	return ids
}

func TestEvaluateReportsAllViolationsSorted(t *testing.T) {
	ps, err := loadPolicies("../../policies")
	if err != nil {
		t.Fatal(err)
	}
	in := toolInput{Command: "cat ~/.ssh/id_rsa && rm -rf /opt"}

	want := []string{"CMD-001", "DATA-002b"}
	for i := 0; i < 20; i++ {
		got := violationIDs(evaluate(ps, "Bash", in))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("violations = %v, want %v", got, want)
		}
	}
}

func TestEvaluateAllowsEverydayCommands(t *testing.T) {
	ps, err := loadPolicies("../../policies")
	if err != nil {
		t.Fatal(err)
	}
	commands := []string{
		"go test ./...",
		"git status && git diff | head -50",
		"npm install && npm run build",
		"ls -la ~/project",
		"cat /etc/hosts",
		"rm -rf ./node_modules",
		"rm -f build.log",
		"echo $(date)",
		"docker ps | grep api",
		"grep -r TODO src/ | wc -l",
		"FOO=bar make test",
	}
	for _, c := range commands {
		if got := violationIDs(evaluate(ps, "Bash", toolInput{Command: c})); len(got) > 0 {
			t.Errorf("%q unexpectedly blocked by %v", c, got)
		}
	}
}

func TestCommandVariantsCanonicalizesRm(t *testing.T) {
	cases := map[string]string{
		"rm -fr /x":             "rm -rf /x",
		"rm --recursive /x":     "rm -rf /x",
		"/bin/rm -r -f /x":      "rm -rf /x",
		`\rm -rf -- /x`:         "rm -rf /x",
		"FOO=1 nohup rm -Rf /x": "rm -rf /x",
		"rm /x":                 "rm /x",
	}
	for in, want := range cases {
		found := false
		for _, v := range commandVariants(in) {
			if v == want {
				found = true
			}
		}
		if !found {
			t.Errorf("commandVariants(%q) = %q, missing %q", in, commandVariants(in), want)
		}
	}
}
