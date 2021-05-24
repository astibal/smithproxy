### developer's todo notes

- Revisit regex search functions which return single result per a go. 

    They shoud return a container of matches. We can be missing some signature hits!
    
    ```c++
        range search_function(std::string &expr, std::string &str) override 
    ```
