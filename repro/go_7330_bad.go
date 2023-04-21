package main
import "fmt"
import "time"
func main() {
    count := 0
    t1 := time.Now()
    for i := 0; i < 1000000000; i++ {
        count += i
    }
    fmt.Printf("%d sum:%d\n", time.Now().Sub(t1), count)
}
