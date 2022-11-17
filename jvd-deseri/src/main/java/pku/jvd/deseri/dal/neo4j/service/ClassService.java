package pku.jvd.deseri.dal.neo4j.service;

import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pku.jvd.deseri.config.GlobalConfiguration;
import pku.jvd.deseri.dal.neo4j.repository.ClassRefRepository;
import pku.jvd.deseri.dal.neo4j.repository.MethodRefRepository;
import pku.jvd.deseri.util.FileUtils;

@Service
public class ClassService {
    private static final Log log = LogFactory.get(ClassService.class);
    @Autowired
    private ClassRefRepository classRefRepository;
    @Autowired
    private MethodRefRepository methodRefRepository;


    public void clear(){
        classRefRepository.clearAll();
//        classRefRepository.deleteAll();
//        methodRefRepository.deleteAll();
    }

    public void importClassRef(){
        if(FileUtils.fileExists(GlobalConfiguration.CLASSES_CACHE_PATH)){
            classRefRepository.loadClassRefFromCSV(
                    FileUtils.getWinPath(GlobalConfiguration.CLASSES_CACHE_PATH));
        }
    }

    public void buildEdge(){
        if(FileUtils.fileExists(GlobalConfiguration.EXTEND_RELATIONSHIP_CACHE_PATH)){
            log.info("Save Extend relationship");
            classRefRepository.loadExtendEdgeFromCSV(
                    FileUtils.getWinPath(GlobalConfiguration.EXTEND_RELATIONSHIP_CACHE_PATH));
        }
        if(FileUtils.fileExists(GlobalConfiguration.INTERFACE_RELATIONSHIP_CACHE_PATH)){
            log.info("Save Interface relationship");
            classRefRepository.loadInterfacesEdgeFromCSV(
                    FileUtils.getWinPath(GlobalConfiguration.INTERFACE_RELATIONSHIP_CACHE_PATH));
        }
        if(FileUtils.fileExists(GlobalConfiguration.HAS_RELATIONSHIP_CACHE_PATH)){
            log.info("Save Has relationship");
            classRefRepository.loadHasEdgeFromCSV(
                    FileUtils.getWinPath(GlobalConfiguration.HAS_RELATIONSHIP_CACHE_PATH));
        }
        if(FileUtils.fileExists(GlobalConfiguration.CALL_RELATIONSHIP_CACHE_PATH)){
            log.info("Save Call relationship");
            methodRefRepository.loadCallEdgeFromCSV(
                    FileUtils.getWinPath(GlobalConfiguration.CALL_RELATIONSHIP_CACHE_PATH));
        }
        if(FileUtils.fileExists(GlobalConfiguration.ALIAS_RELATIONSHIP_CACHE_PATH)){
            log.info("Save Alias relationship");
            methodRefRepository.loadAliasEdgeFromCSV(
                    FileUtils.getWinPath(GlobalConfiguration.ALIAS_RELATIONSHIP_CACHE_PATH));
        }
    }

}
