project_root="/Users/fedejinich/Projects/hhejava"

go run test_generator.go && \
    mv test_*.json "${project_root}/src/test/resources" 
