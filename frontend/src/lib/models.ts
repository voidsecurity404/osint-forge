export namespace config {
	
	export class Config {
	    securitytrails_key: string;
	    virustotal_key: string;
	    nvd_key: string;
	    nmap_args: string;
	    http_user_agent: string;
	    max_concurrent: number;
	    fuzz_enabled: boolean;
	    fuzz_wordlist: string;
	    subdomain_bruteforce: boolean;
	    zone_transfer: boolean;
	    status_codes: string;
	    scan_timeout_min: number;
	    scope_strict: boolean;
	    extra_scope: string[];
	    rate_limit_per_host: number;
	    shodan_key: string;
	    censys_id: string;
	    censys_secret: string;
	    hibp_key: string;
	    github_token: string;
	    nuclei: boolean;
	    screenshots: boolean;
	    favicon_hash: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.securitytrails_key = source["securitytrails_key"];
	        this.virustotal_key = source["virustotal_key"];
	        this.nvd_key = source["nvd_key"];
	        this.nmap_args = source["nmap_args"];
	        this.http_user_agent = source["http_user_agent"];
	        this.max_concurrent = source["max_concurrent"];
	        this.fuzz_enabled = source["fuzz_enabled"];
	        this.fuzz_wordlist = source["fuzz_wordlist"];
	        this.subdomain_bruteforce = source["subdomain_bruteforce"];
	        this.zone_transfer = source["zone_transfer"];
	        this.status_codes = source["status_codes"];
	        this.scan_timeout_min = source["scan_timeout_min"];
	        this.scope_strict = source["scope_strict"];
	        this.extra_scope = source["extra_scope"];
	        this.rate_limit_per_host = source["rate_limit_per_host"];
	        this.shodan_key = source["shodan_key"];
	        this.censys_id = source["censys_id"];
	        this.censys_secret = source["censys_secret"];
	        this.hibp_key = source["hibp_key"];
	        this.github_token = source["github_token"];
	        this.nuclei = source["nuclei"];
	        this.screenshots = source["screenshots"];
	        this.favicon_hash = source["favicon_hash"];
	    }
	}

}

export namespace core {
	
	export class LogLine {
	    source: string;
	    level: string;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new LogLine(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.source = source["source"];
	        this.level = source["level"];
	        this.message = source["message"];
	    }
	}
	export class Progress {
	    phase: string;
	    done: number;
	    total: number;
	    running: string;
	    nodes: number;
	    edges: number;
	    finished: boolean;
	    startedAt: number;
	
	    static createFrom(source: any = {}) {
	        return new Progress(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.phase = source["phase"];
	        this.done = source["done"];
	        this.total = source["total"];
	        this.running = source["running"];
	        this.nodes = source["nodes"];
	        this.edges = source["edges"];
	        this.finished = source["finished"];
	        this.startedAt = source["startedAt"];
	    }
	}
	export class Target {
	    raw: string;
	    isIP: boolean;
	    ip: string;
	    domain: string;
	
	    static createFrom(source: any = {}) {
	        return new Target(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.raw = source["raw"];
	        this.isIP = source["isIP"];
	        this.ip = source["ip"];
	        this.domain = source["domain"];
	    }
	}

}

export namespace graph {
	
	export class Edge {
	    id: string;
	    source: string;
	    target: string;
	    label: string;
	
	    static createFrom(source: any = {}) {
	        return new Edge(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.source = source["source"];
	        this.target = source["target"];
	        this.label = source["label"];
	    }
	}
	export class Node {
	    id: string;
	    type: string;
	    label: string;
	    props?: Record<string, any>;
	
	    static createFrom(source: any = {}) {
	        return new Node(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.type = source["type"];
	        this.label = source["label"];
	        this.props = source["props"];
	    }
	}
	export class Delta {
	    nodes: Node[];
	    edges: Edge[];
	
	    static createFrom(source: any = {}) {
	        return new Delta(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.nodes = this.convertValues(source["nodes"], Node);
	        this.edges = this.convertValues(source["edges"], Edge);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	

}

export namespace history {
	
	export class Diff {
	    target: string;
	    // Go type: time
	    previous: any;
	    added: graph.Node[];
	    removed: graph.Node[];
	    hasPrevious: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Diff(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target = source["target"];
	        this.previous = this.convertValues(source["previous"], null);
	        this.added = this.convertValues(source["added"], graph.Node);
	        this.removed = this.convertValues(source["removed"], graph.Node);
	        this.hasPrevious = source["hasPrevious"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace scan {
	
	export class Page {
	    url: string;
	    status: number;
	    server: string;
	    title: string;
	    body: string;
	
	    static createFrom(source: any = {}) {
	        return new Page(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.url = source["url"];
	        this.status = source["status"];
	        this.server = source["server"];
	        this.title = source["title"];
	        this.body = source["body"];
	    }
	}

}

