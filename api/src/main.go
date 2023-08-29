package main

import "net/http"

type SimpleServer struct {
}

func (s *SimpleServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

func (s *SimpleServer) Get(resp http.ResponseWriter, req *http.Request) error {
	return nil
}

func main() {
	http.ListenAndServe(":8080", &SimpleServer{})
}
