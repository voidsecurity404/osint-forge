package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"osint-forge/internal/config"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	addr := flag.String("addr", "127.0.0.1:8081", "адрес для прослушивания (0.0.0.0:8081 откроет доступ из сети — авторизации нет!)")
	open := flag.Bool("open", false, "открыть интерфейс в браузере при запуске")
	flag.Parse()

	app := NewApp()
	defer app.shutdown()

	app.monitor = NewMonitor(app)
	if dir, err := config.Dir(); err == nil {
		if err := app.monitor.Persist(filepath.Join(dir, "monitor.json")); err != nil {
			log.Printf("не удалось загрузить наблюдения мониторинга: %v", err)
		}
	}
	app.OnScanDone(app.monitor.onScanDone)
	app.monitor.Start()

	dist, err := fs.Sub(assets, "frontend/dist")
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           newRouter(app, dist),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	url := "http://" + displayAddr(*addr)
	fmt.Printf("🚀 Веб-интерфейс osint-forge: %s\n", url)
	if *open {
		openBrowser(url)
	}

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	fmt.Println("\n⏹  остановка…")
	app.CancelScan()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func displayAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
