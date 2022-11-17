package pku.jvd.deseri;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import pku.jvd.deseri.dal.neo4j.repository.ClassRefRepository;

@SpringBootTest(classes = DeseriMainService.class)
public class test {
    @Autowired
    private ClassRefRepository classRefRepository;
//
//    @Test
//    public void runDepth() {
//        classRefRepository.testDepth();
//    }
}


