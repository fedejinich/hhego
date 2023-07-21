cd jni &&\
    go run test_generator.go && \
    mv output.json ../../../hhejava/src/test/resources
