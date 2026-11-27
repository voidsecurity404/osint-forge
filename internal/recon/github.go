package recon

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// GitHubSource searches public GitHub code for mentions of the target domain —
// a common way leaked configs, keys and internal hostnames surface. Requires a
// token (code search needs authentication); skipped when absent.
type GitHubSource struct{ Cfg config.Config }

func (GitHubSource) Name() string      { return "github" }
func (GitHubSource) Stage() core.Stage { return core.StageEnrich }
func (s GitHubSource) Applicable(t core.Target) bool {
	return s.Cfg.GitHubToken != "" && t.Domain != ""
}

type githubCodeSearch struct {
	TotalCount int `json:"total_count"`
	Items      []struct {
		Path    string `json:"path"`
		HTMLURL string `json:"html_url"`
		Repo    struct {
			FullName string `json:"full_name"`
			HTMLURL  string `json:"html_url"`
		} `json:"repository"`
	} `json:"items"`
}

func (s GitHubSource) Run(ctx context.Context, c *core.Collector) error {
	domain := c.Target.Domain
	q := url.Values{"q": {"\"" + domain + "\""}, "per_page": {"30"}}
	endpoint := "https://api.github.com/search/code?" + q.Encode()
	headers := map[string]string{
		"Authorization":        "Bearer " + s.Cfg.GitHubToken,
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	var res githubCodeSearch
	if err := getJSON(ctx, s.Cfg, endpoint, headers, &res); err != nil {
		return fmt.Errorf("github: %w", err)
	}
	if res.TotalCount == 0 || len(res.Items) == 0 {
		c.Log(core.LogInfo, "github: совпадений в коде нет")
		return nil
	}

	domID := graph.NodeID(graph.NodeDomain, domain)
	repos := map[string]bool{}
	for _, it := range res.Items {
		repos[it.Repo.FullName] = true
		label := it.Repo.FullName + "/" + it.Path
		uID := c.Node(graph.NodeURL, it.HTMLURL, label, map[string]any{
			"source": "github", "repo": it.Repo.FullName, "path": it.Path,
		})
		c.Edge(domID, uID, "github_mention")
	}
	repoNames := make([]string, 0, len(repos))
	for r := range repos {
		repoNames = append(repoNames, r)
	}
	c.Finding("medium", "github:"+domain,
		fmt.Sprintf("Домен упоминается на GitHub: %d результатов (%d репозиториев)", res.TotalCount, len(repos)),
		"Домен встречается в коде следующих репозиториев GitHub — проверьте их на утёкшие конфигурации и ключи: "+strings.Join(repoNames, ", "),
		domID)
	c.Log(core.LogWarn, fmt.Sprintf("github: %d совпадений в %d репозиториях", res.TotalCount, len(repos)))
	c.Flush()
	return nil
}
