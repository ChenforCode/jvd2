package pku.jvd.deseri.dal.neo4j.service;

import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pku.jvd.deseri.config.GlobalConfiguration;
import pku.jvd.deseri.dal.neo4j.repository.MethodRefRepository;
import pku.jvd.deseri.util.FileUtils;

@Service
public class MethodService {
    private static final Log log = LogFactory.get(MethodService.class);
    @Autowired
    private MethodRefRepository methodRefRepository;

    public void importMethodRef(){
        if(FileUtils.fileExists(GlobalConfiguration.METHODS_CACHE_PATH)){
            methodRefRepository.loadMethodRefFromCSV(
                    FileUtils.getWinPath(GlobalConfiguration.METHODS_CACHE_PATH));
        }
    }

    public MethodRefRepository getRepository(){
        return methodRefRepository;
    }
}
