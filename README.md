# To set up software dependencies, run:

`./setup.sh`

# Where to find data for each bug:

For go-909 (https://github.com/golang/go/issues/909): 

`git checkout go_909_32bit`
`git lfs pull`

For go-7330 (https://github.com/golang/go/issues/7330): 

`git checkout go_7330`
`git lfs pull`

For go-8832 (https://github.com/golang/go/issues/8832): 

`git checkout go_8332`
`git lfs pull`

For go-11068 (https://github.com/golang/go/issues/11068): 

`git checkout go_11068`
`git lfs pull`

For go-12228 (https://github.com/golang/go/issues/12228): 

`git checkout go_12228_fast`
`git lfs pull`

`git checkout go_12228_slow`
`git lfs pull`

For go-13552 (https://github.com/golang/go/issues/13552): 

`git checkout go_13552_slow`
`git lfs pull`

For mongodb-44991 (https://jira.mongodb.org/browse/SERVER-44991): 

`git checkout mongodb_44991_slow`
`git lfs pull`

For mongodb-56274 (https://jira.mongodb.org/browse/SERVER-56274): 

`git checkout mongodb_56274_slow`
`git lfs pull`

For mongodb-57221 (https://jira.mongodb.org/browse/SERVER-57221): 

`git checkout mongodb_57221_slow`
`git lfs pull`

For coreutils-930965 (https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=930965): 

`git checkout coreutils_930965`
`git lfs pull`

For coreutils-1014738 (https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1014738): 

`git checkout coreutils_1014738`
`git lfs pull`

For redis-7595 (https://github.com/redis/redis/issues/7595):

`git checkout redis_7595`
`git lfs pull`

# To reproduce the results:

Step.1

change the current directory in analysis.config

change the current directory in relation_analysis.config

Step.2

`./compile.sh`

Step.3

`python3.7 compare_relations.py`

# For detailed manual, see:

https://docs.google.com/document/d/17qUF55PS_XGMB8MyapEzgbwEnDeTgU6bVfcE0VUv2L0/edit?usp=sharing

# For help with interpreting the outputs of each case, see:

https://docs.google.com/document/d/1w42JbDzXIhMbAJtFdiq1Zq2y9J_i8-JhQcKvPH0liQI/edit?usp=sharing
