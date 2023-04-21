package main 
import "fmt"
func main() {
    count := 0
    for i := 0; i < 1000000000; i++ {
        count += i
    }
    fmt.Printf("sum:%d\n", count)
}
