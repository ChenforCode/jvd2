package pku.jvd.deseri.dal.neo4j.repository;

import org.neo4j.driver.internal.value.PathValue;
import org.springframework.data.neo4j.repository.Neo4jRepository;
import org.springframework.data.neo4j.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import pku.jvd.deseri.dal.neo4j.entity.ClassEntity;

import java.nio.file.Path;
import java.util.List;

@Repository
public interface ClassRefRepository extends Neo4jRepository<ClassEntity, String> {

    @Query("CALL apoc.periodic.iterate(\"CALL apoc.load.csv('file://\"+$path+\"', " +
            "{header:true, mapping:{ " +
            "IS_INTERFACE: {type:'boolean'}, " +
            "HAS_SUPER_CLASS: {type:'boolean'}, " +
            "HAS_INTERFACES: {type:'boolean'}, " +
            "IS_ABSTRACT: {type:'boolean'}, " +
            "IS_INITIALED: {type:'boolean'}, " +
            "IS_STRUTS_ACTION: {type:'boolean'}, " +
            "HAS_DEFAULT_CONSTRUCTOR: {type:'boolean'}, " +
            "IS_SERIALIZABLE:{type:'boolean'}}}) YIELD map AS row RETURN row\",\"MERGE (c:Class {NAME:row.NAME}) ON CREATE SET c = row\", {batchSize:5000, iterateList:true, parallel:true}) yield total")
    int loadClassRefFromCSV(String path);

    @Query("CALL apoc.periodic.iterate(\"CALL apoc.load.csv('file://\"+$path+\"', {header:true}) YIELD map AS row RETURN row\",\"MATCH( c1:Class {NAME:row.SOURCE} ) MATCH ( c2:Class { NAME:row.TARGET } ) MERGE (c1) -[e:EXTENDS { ID:row.ID }] -> (c2)\", {batchSize:1000, iterateList:true, parallel:false}) yield total")
    int loadExtendEdgeFromCSV(String path);

    @Query("CALL apoc.periodic.iterate(\"CALL apoc.load.csv('file://\"+$path+\"', {header:true}) YIELD map AS row RETURN row\",\"MATCH( c1:Class {NAME:row.SOURCE} ) MATCH ( c2:Class { NAME:row.TARGET } ) MERGE (c1) -[e:INTERFACE { ID:row.ID }] -> (c2)\", {batchSize:1000, iterateList:true, parallel:false}) yield total")
    int loadInterfacesEdgeFromCSV(String path);

    @Query("CALL apoc.periodic.iterate(\"CALL apoc.load.csv('file://\"+$path+\"', {header:true}) YIELD map AS row RETURN row\",\"MATCH(c:Class{NAME:row.CLASS_REF}) MATCH(m:Method { ID:row.METHOD_REF }) MERGE (c) -[e:HAS { ID:row.ID }]-> (m)\", {batchSize:1000, iterateList:true, parallel:false}) yield total")
    int loadHasEdgeFromCSV(String path);

    @Query("CALL apoc.periodic.iterate(\"match (n) return n\",\"detach delete n\", {batchSize:10000, iterateList:true, parallel:false}) yield total")
    int clearAll();

    @Query("match (source:Method {NAME: $sourceName})\n" +
            "match (sink:Method {NAME: $sinkName})<-[:CALL]-(m1:Method)\n" +
            "call apoc.algo.allSimplePaths(source, m1, \"<CALL|ALIAS\", $depth) yield path \n" +
            "return path")
    List<PathValue> search2(String sourceName,
                            String sinkName,
                            Integer depth);

    @Query("match (source:Method {NAME:$sourceName})\n" +
            "match (sink:Method {NAME:$sinkName, CLASSNAME:$sinkClassName})<-[:CALL]-(m1:Method)\n" +
            "call apoc.algo.allSimplePaths(m1, source, \"<CALL|ALIAS\", $depth) yield path \n" +
            "return path limit 10")
    List<PathValue> search3(@Param("sourceName") String sourceName,
                            @Param("sinkName") String sinkName,
                            @Param("sinkClassName") String sinkClassName,
                            @Param("depth") Integer depth);

    @Query("match (source:Method {NAME:$sourceName})\n" +
            "match (sink:Method {IS_SINK:true, NAME:$sinkName})<-[:CALL]-(m1:Method)\n" +
            "call apoc.algo.allSimplePaths(m1, source, \"<CALL|ALIAS\", $depth) yield path \n" +
            "return path limit 50")
    List<PathValue> search4(@Param("sourceName") String sourceName,
                            @Param("sinkName") String sinkName,
                            @Param("depth") Integer depth);

    //3.1cc + jdk8_051
    @Query("match path=(m:Method {SIGNATURE:\"<sun.reflect.annotation.AnnotationInvocationHandler: void readObject(java.io.ObjectInputStream)>\"})-[:CALL]->(m2:Method{NAME:\"setValue\"})-[:ALIAS*]->(m3:Method{NAME:\"setValue\", CLASSNAME:\"org.apache.commons.collections.map.AbstractInputCheckedMapDecorator$MapEntry\"})-[:CALL]->(m4:Method{NAME:\"checkSetValue\"})-[:ALIAS*]->(m5:Method{NAME:\"checkSetValue\", CLASSNAME:\"org.apache.commons.collections.map.TransformedMap\"})-[:CALL]->(m6:Method{NAME:\"transform\"}) return path")
    List<PathValue> cc1();

    @Query("match path=(m1:Method {SIGNATURE:\"<java.util.PriorityQueue: void readObject(java.io.ObjectInputStream)>\"})-[:CALL ]->(m2:Method {NAME:\"heapify\"})-[:CALL ]->(m3)-[:CALL]->(m4:Method {NAME:\"siftDownUsingComparator\"})-[:CALL]->(m5)-[:ALIAS*]-(m6 {SIGNATURE:\"<org.apache.commons.collections.comparators.TransformingComparator: int compare(java.lang.Object,java.lang.Object)>\"})-[:CALL]->(m7)-[:ALIAS*]-(m8:Method)-[:CALL]->(m9:Method {IS_SINK:true}) return path")
    List<PathValue> cc2();

    @Query("match path=(m1:Method {SIGNATURE:\"<java.util.PriorityQueue: void readObject(java.io.ObjectInputStream)>\"})-[:CALL ]->(m2:Method {NAME:\"heapify\"})-[:CALL ]->(m3)-[:CALL ]->(m4:Method {NAME:\"siftDownUsingComparator\"})-[:CALL ]->(m5)-[:ALIAS*]-(m6 {SIGNATURE:\"<org.apache.commons.collections.comparators.TransformingComparator: int compare(java.lang.Object,java.lang.Object)>\"})-[:CALL ]->(m7)-[:ALIAS*]-(m8:Method)-[:CALL ]->(m9:Method {NAME:\"newInstance\"}) return path")
    List<PathValue> cc4();

    @Query("match path=(m1:Method {SIGNATURE:\"<javax.management.BadAttributeValueExpException: void readObject(java.io.ObjectInputStream)>\"})-[:CALL]->(m2:Method {NAME:\"toString\"})-[:ALIAS*]->(m3:Method {SIGNATURE:\"<org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.String toString()>\"})-[:CALL]->(m4:Method {NAME:\"getValue\"})-[:CALL]->(m5:Method {NAME:\"get\"})-[:ALIAS*1..2]-(m6:Method {NAME:\"get\"})-[:CALL]->(m7:Method {NAME:\"transform\"})-[:ALIAS*]-(m8:Method)-[:CALL]->(m9:Method {IS_SINK:true}) return path")
    List<PathValue> cc5();

    @Query("match path=(m1:Method {SIGNATURE:\"<java.util.HashSet: void readObject(java.io.ObjectInputStream)>\"})-[:CALL]->(m2:Method{CLASSNAME:\"java.util.HashMap\", NAME:\"put\"})-[:CALL]->(m3:Method{CLASSNAME:\"java.util.HashMap\", NAME:\"hash\"})-[:CALL]->(m4:Method{CLASSNAME:\"java.lang.Object\", NAME:\"hashCode\"})-[:ALIAS*..5]->(m5:Method{CLASSNAME:\"org.apache.commons.collections.keyvalue.TiedMapEntry\", NAME:\"hashCode\"})-[:CALL]->(m6:Method{CLASSNAME:\"org.apache.commons.collections.keyvalue.TiedMapEntry\", NAME:\"getValue\"})-[:CALL]->(m7:Method{CLASSNAME:\"java.util.Map\", NAME:\"get\"})-[:ALIAS]->(m8:Method{CLASSNAME:\"org.apache.commons.collections.map.LazyMap\", NAME:\"get\"})-[:CALL]->(m9:Method {NAME:\"transform\"})-[:ALIAS*]-(m10:Method)-[:CALL]->(m11:Method {IS_SINK:true}) return path")
    List<PathValue> cc6();

    @Query("match path=(m1:Method {SIGNATURE:\"<java.util.Hashtable: void readObject(java.io.ObjectInputStream)>\"})-[:CALL ]->(m2:Method {NAME:\"reconstitutionPut\"})-[:CALL ]->(m3:Method {NAME:\"equals\"})-[:ALIAS*..2]-(m4:Method)-[:CALL ]->(m5:Method {NAME:\"get\"})-[:ALIAS*1..2]-(m6:Method {NAME:\"get\"})-[:CALL]->(m7:Method {NAME:\"transform\"})-[:ALIAS*]-(m8:Method)-[:CALL]->(m9:Method {IS_SINK:true})  return path")
    List<PathValue> cc7();

    //需要cc4
    @Query("match path=(m1:Method {SIGNATURE:\"<org.apache.commons.collections4.bag.TreeBag: void readObject(java.io.ObjectInputStream)>\"})-[:CALL ]->(m2:Method {NAME:\"doReadObject\"})-[:CALL ]->(m3:Method {NAME:\"put\"})-[:ALIAS*1..4]-(m4:Method)-[:CALL ]->(m5:Method {NAME:\"compare\"})-[:CALL ]->(m6:Method)-[:ALIAS*]-(m7:Method {SIGNATURE:\"<org.apache.commons.collections4.comparators.TransformingComparator: int compare(java.lang.Object,java.lang.Object)>\"})-[:CALL ]->(m8)-[:ALIAS*]-(m9:Method)-[:CALL*..5 ]->(m10:Method {IS_SINK:true}) return path")
    List<PathValue> cc8();

    @Query("match path=(m1:Method {SIGNATURE:\"<java.util.Hashtable: void readObject(java.io.ObjectInputStream)>\"})-[:CALL]->(m2:Method {NAME:\"reconstitutionPut\"})-[:CALL]->(m3:Method {NAME:\"hashCode\"})-[:ALIAS*]->(m4:Method {SIGNATURE:\"<org.apache.commons.collections.keyvalue.TiedMapEntry: int hashCode()>\"})-[:CALL]->(m5:Method {NAME:\"getValue\"})-[:CALL]->(m6:Method {NAME:\"get\"})-[:ALIAS*1..2]->(m7:Method {NAME:\"get\"})-[:CALL]->(m8:Method {NAME:\"transform\"})-[:ALIAS*]->(m9:Method)-[:CALL]->(m10:Method {IS_SINK:true}) return path")
    List<PathValue> cc9();


    @Query("match (source:Method {NAME:\"compareTo\",CLASSNAME:\"javax.naming.ldap.Rdn$RdnEntry\"}) \n" +
            "match (m1:Method {CLASSNAME:\"com.sun.org.apache.xml.internal.dtm.ref.IncrementalSAXSource_Xerces\",NAME:\"parseSome\"})\n" +
            "call apoc.algo.allSimplePaths(m1, source, \"<CALL|ALIAS\", 15) yield path return path limit 20")
    List<PathValue> cve2021_21351();

    @Query("match path=(source:Method {NAME:\"compare\",CLASSNAME:\"sun.awt.datatransfer.DataTransferer$IndexOrderComparator\"})-[:CALL]->(m1:Method {NAME:\"compareIndices\"})-[:CALL]->(m2:Method {NAME:\"get\"})-[:ALIAS*..3]->(m3:Method {CLASSNAME:\"com.sun.xml.internal.ws.client.ResponseContext\"})-[:CALL]->(m4:Method {NAME:\"getAttachments\"})-[:ALIAS*..3]->(m5:Method {CLASSNAME:\"com.sun.xml.internal.ws.encoding.xml.XMLMessage$XMLMultiPart\"})-[:CALL]->(m6:Method {NAME:\"getMessage\"})-[:CALL]->(m7:Method {NAME:\"getInputStream\"})-[:ALIAS*..3]->(m8:Method {CLASSNAME:\"com.sun.xml.internal.ws.message.JAXBAttachment\"})-[:CALL]->(m9:Method {NAME:\"asInputStream\"})-[:CALL]->(m10:Method {NAME:\"writeTo\"})-[:CALL]->(m11:Method {NAME:\"marshal\"})-[:ALIAS*..3]->(m12:Method {SIGNATURE:\"<com.sun.xml.internal.ws.db.glassfish.BridgeWrapper: void marshal(java.lang.Object,java.io.OutputStream,javax.xml.namespace.NamespaceContext,javax.xml.bind.attachment.AttachmentMarshaller)>\"})-[:CALL]->(m13:Method {NAME:\"marshal\"})-[:CALL]->(m14:Method {NAME:\"marshal\"})-[:ALIAS*..3]->(m15:Method {CLASSNAME:\"com.sun.xml.internal.bind.v2.runtime.BridgeImpl\"})-[:CALL]->(m16:Method {NAME:\"write\"})-[:CALL]->(m17:Method {NAME:\"childAsXsiType\"})-[:CALL]->(m18:Method {NAME:\"serializeURIs\"})-[:ALIAS]->(m19:Method {CLASSNAME:\"com.sun.xml.internal.bind.v2.runtime.ClassBeanInfoImpl\"})-[:CALL]->(m20:Method {NAME:\"get\"})-[:ALIAS]->(m21:Method {CLASSNAME:\"com.sun.xml.internal.bind.v2.runtime.reflect.Accessor$GetterSetterReflection\"})-[:CALL]->(m22:Method {IS_SINK:true, NAME:\"invoke\"}) return path")
    List<PathValue> cve2021_21345();

    @Query("match (source:Method {NAME:\"compareTo\",CLASSNAME:\"javax.naming.ldap.Rdn$RdnEntry\"})-[:CALL]->(m2:Method {NAME:\"equals\"})-[:ALIAS*..3]->(m3:Method {CLASSNAME:\"com.sun.org.apache.xpath.internal.objects.XString\"}) match (sink:Method {IS_SINK:true,NAME:\"invoke\"})<-[:CALL]-(m1:Method {CLASSNAME:\"sun.swing.SwingLazyValue\",NAME:\"createValue\"}) call apoc.algo.allSimplePaths(m1, m3, \"<CALL|ALIAS\", 12) yield path return path limit 20")
    List<PathValue> cve2021_21364();


    @Query("match (source:Method{NAME:$source})\n" +
            "match (sink:Method) where sink.NAME in $sinkMethod and sink.CLASSNAME in $sinkClass\n" +
            "call apoc.algo.allSimplePaths(sink, source, \"<CALL|ALIAS\", $depth) yield path \n" +
            "return path limit 500")
    List<PathValue> searchSource(String source, List<String> sinkMethod, List<String> sinkClass, int depth);

    @Query("match (source:Method) where source.SIGNATURE in $sourceSig\n" +
            "match (sink:Method) where sink.NAME in $sinkMethod and sink.CLASSNAME in $sinkClass\n" +
            "call apoc.algo.allSimplePaths(sink, source, \"<CALL|ALIAS\", $depth) yield path \n" +
            "return path limit 500")
    List<PathValue> searchSourceInSig(List<String> sourceSig, List<String> sinkMethod, List<String> sinkClass, int depth);

    @Query("match (source:Method where source.NAME in $sources)\n" +
            "match (sink:Method) where sink.NAME in $sinkMethod and sink.CLASSNAME in $sinkClass\n" +
            "call apoc.algo.allSimplePaths(sink, source, \"<CALL|ALIAS\", $depth) yield path \n" +
            "return path limit 500")
    List<PathValue> searchSourceList(List<String> sources, List<String> sinkMethod, List<String> sinkClass, int depth);

    @Query("match path=(m:Method {NAME:\"writeValueAsString\", CLASSNAME:\"com.fasterxml.jackson.databind.ObjectMapper\"})-[:CALL]->(m2:Method {NAME:\"_configAndWriteValue\", CLASSNAME:\"com.fasterxml.jackson.databind.ObjectMapper\"})-[:CALL]->(m3:Method {NAME:\"serializeValue\", CLASSNAME:\"com.fasterxml.jackson.databind.ser.DefaultSerializerProvider\"})-[:CALL]->(m4:Method {NAME:\"serialize\"})-[:ALIAS*]->(m6:Method {NAME:\"serialize\", CLASSNAME:\"com.fasterxml.jackson.databind.ser.BeanSerializer\"})-[:CALL]->(m7:Method {NAME:\"serializeFields\"})-[:CALL]->(m8:Method {NAME:\"serializeAsField\"})-[:CALL]->(m9:Method {NAME:\"invoke\"})  return path")
    List<PathValue> jacksonSerialize();

    @Query("match path=(m:Method {NAME:\"readValue\", CLASSNAME:\"com.fasterxml.jackson.databind.ObjectMapper\"})-[:CALL]->(m2:Method {NAME:\"_readMapAndClose\", CLASSNAME:\"com.fasterxml.jackson.databind.ObjectMapper\"})-[:CALL]->(m3:Method {NAME:\"deserialize\", CLASSNAME:\"com.fasterxml.jackson.databind.JsonDeserializer\"})-[:ALIAS*]->(m4:Method {NAME:\"deserialize\", CLASSNAME:\"com.fasterxml.jackson.databind.deser.impl.TypeWrappedDeserializer\"})-[:CALL]->(m5:Method {NAME:\"deserializeWithType\", CLASSNAME:\"com.fasterxml.jackson.databind.JsonDeserializer\"})-[:ALIAS*]->(m6:Method {NAME:\"deserializeWithType\", CLASSNAME:\"com.fasterxml.jackson.databind.deser.std.UntypedObjectDeserializer$Vanilla\"})-[:CALL]->(m7:Method {NAME:\"deserializeTypedFromAny\", CLASSNAME:\"com.fasterxml.jackson.databind.jsontype.TypeDeserializer\"})-[:ALIAS*]->(m8:Method {NAME:\"deserializeTypedFromAny\", CLASSNAME:\"com.fasterxml.jackson.databind.jsontype.impl.AsArrayTypeDeserializer\"})-[:CALL]->(m9:Method {NAME:\"_deserialize\"})-[:CALL]->(m10:Method {NAME:\"deserialize\"})-[:ALIAS*]->(m11:Method {NAME:\"deserialize\", CLASSNAME:\"com.fasterxml.jackson.databind.deser.BeanDeserializer\"})-[:CALL]->(m12:Method {NAME:\"vanillaDeserialize\"})-[:CALL]->(m13:Method {NAME:\"deserializeAndSet\"})-[:ALIAS*]->(m14:Method {NAME:\"deserializeAndSet\", CLASSNAME:\"com.fasterxml.jackson.databind.deser.impl.MethodProperty\"})-[:CALL]->(m15:Method {NAME:\"invoke\"}) return path")
    List<PathValue> jacksonDeserialize();


    @Query("match path=(m:Method {NAME:\"getConnection\", CLASSNAME:\"ch.qos.logback.core.db.DriverManagerConnectionSource\"})-[:CALL]->(m2:Method {NAME: \"getConnection\", CLASSNAME:\"java.sql.DriverManager\"}) return path")
    List<PathValue> Serialize_CVE_2019_12384();

    @Query("match path=(m:Method {NAME:\"getConnection\", CLASSNAME:\"ch.qos.logback.core.db.JNDIConnectionSource\"})-[:CALL]->(m2:Method {NAME: \"lookupDataSource\"})-[:CALL]->(m3:Method {NAME: \"lookup\", CLASSNAME: \"javax.naming.Context\"}) return path")
    List<PathValue> Serialize_CVE_2019_14439();

    @Query("match path=(m:Method {NAME:\"getTransactionManager\", CLASSNAME:\"org.apache.openjpa.ee.RegistryManagedRuntime\"})-[:CALL]->(m2:Method {NAME: \"lookup\", CLASSNAME:\"javax.naming.Context\"}) return path")
    List<PathValue> Serialize_CVE_2020_11113();

    @Query("match path=(m:Method {NAME:\"getConnection\", CLASSNAME: \"oadd.org.apache.xalan.lib.sql.JNDIConnectionPool\"})-[:CALL]->(m2:Method {NAME: \"findDatasource\"})-[:CALL]->(m3:Method {NAME: \"lookup\", CLASSNAME: \"javax.naming.InitialContext\"}) return path")
    List<PathValue> Serialize_CVE_2020_14060();

    @Query("match path=(m:Method {NAME:\"getConnection\", CLASSNAME: \"com.sun.org.apache.xalan.internal.lib.sql.JNDIConnectionPool\"})-[:CALL]->(m2:Method {NAME: \"findDatasource\"})-[:CALL]->(m3:Method {NAME: \"lookup\", CLASSNAME: \"javax.naming.InitialContext\"}) return path")
    List<PathValue> Serialize_CVE_2020_14062();

    @Query("match path=(m:Method {NAME:\"getRealms\", CLASSNAME: \"org.jsecurity.realm.jndi.JndiRealmFactory\"})-[:CALL]->(m2:Method {NAME: \"lookup\"}) return path")
    List<PathValue> Serialize_CVE_2020_14195();

    @Query("match path=(m:Method {NAME:\"getConnection\", CLASSNAME:\"com.oracle.wls.shaded.org.apache.xalan.lib.sql.JNDIConnectionPool\"})-[:CALL]->(m2:Method {NAME: \"findDatasource\"})-[:CALL]->(m3:Method {NAME: \"lookup\", CLASSNAME:\"javax.naming.InitialContext\"}) return path")
    List<PathValue> Serialize_CVE_2020_35728();

    @Query("match path=(m:Method {NAME:\"getPooledConnection\", CLASSNAME:\"org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS\"})-[:CALL]->(m2:Method {NAME: \"getConnection\"}) return path")
    List<PathValue> Serialize_CVE_2020_36179();

    @Query("match path=(m:Method {NAME:\"getConnection\", CLASSNAME:\"org.apache.tomcat.dbcp.dbcp2.datasources.InstanceKeyDataSource\"})-[:CALL]->(m1:Method {NAME:\"testCPDS\"})-[:CALL]->(m3:Method {NAME:\"lookup\", CLASSNAME: \"javax.naming.Context\"}) return path")
    List<PathValue> Serialize_CVE_2020_36184();

    @Query("match path=(m:Method {NAME:\"getPooledConnectionAndInfo\", CLASSNAME:\"org.apache.tomcat.dbcp.dbcp.datasources.PerUserPoolDataSource\"})-[:CALL]->(m1:Method {NAME:\"registerPool\"})-[:CALL]->(m3:Method {NAME:\"testCPDS\"})-[:CALL]->(m4:Method {NAME:\"lookup\", CLASSNAME:\"javax.naming.Context\"}) return path")
    List<PathValue> Serialize_CVE_2020_36186();

    @Query("match path=(m:Method {NAME:\"getConnection\", CLASSNAME:\"com.newrelic.agent.deps.ch.qos.logback.core.db.JNDIConnectionSource\"})-[:CALL]->(m1:Method {NAME:\"lookupDataSource\"})-[:CALL]->(m3:Method {NAME:\"lookup\", CLASSNAME: \"javax.naming.Context\"}) return path")
    List<PathValue> Serialize_CVE_2020_36188();


    @Query("match path=(m:Method {NAME:\"setMetricRegistry\", CLASSNAME:\"com.zaxxer.hikari.HikariConfig\"})-[:CALL]->(m2:Method {NAME: \"getObjectOrPerformJndiLookup\"})-[:CALL]->(m3:Method {NAME: \"lookup\", CLASSNAME: \"javax.naming.InitialContext\"}) return path")
    List<PathValue> Deserialize_CVE_2019_14540();

    @Query("match path=(m:Method {NAME:\"toObjectImpl\", CLASSNAME:\"org.apache.xbean.propertyeditor.JndiConverter\"})-[:CALL]->(m2:Method {NAME:\"lookup\", CLASSNAME:\"javax.naming.InitialContext\"}) return path")
    List<PathValue> Deserialize_CVE_2020_8840();

    @Query("match path=(m:Method {NAME:\"setMetricRegistry\", CLASSNAME:\"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig\"})-[:CALL]->(m2:Method {NAME: \"lookup\", CLASSNAME:\"javax.naming.InitialContext\"}) return path\n")
    List<PathValue> Deserialize_CVE_2020_9546();

    //搜不到 但从config开始
    @Query("match path=(m:Method {NAME:\"setMetricRegistry\", CLASSNAME:\"br.com.anteros.dbcp.AnterosDBCPDataSource\"})-[:CALL]->(m2:Method {NAME: \"setMetricRegistry\", CLASSNAME: \"br.com.anteros.dbcp.AnterosDBCPConfig\"})-[:CALL]->(m3:Method {NAME: \"getObjectOrPerformJndiLookup\"})-[:CALL]->(m4:Method {NAME: \"lookup\", CLASSNAME: \"javax.naming.InitialContext\"}) return path")
    List<PathValue> Deserialize_CVE_2020_24616();

    @Query("match path=(m:Method {NAME:\"readValue\", CLASSNAME:\"com.fasterxml.jackson.databind.ObjectMapper\"})-[:CALL]->(m2:Method {NAME:\"_readMapAndClose\", CLASSNAME:\"com.fasterxml.jackson.databind.ObjectMapper\"})-[:CALL]->(m3:Method {NAME:\"deserialize\", CLASSNAME:\"com.fasterxml.jackson.databind.JsonDeserializer\"})-[:ALIAS*]->(m4:Method {NAME:\"deserialize\", CLASSNAME:\"com.fasterxml.jackson.databind.deser.impl.TypeWrappedDeserializer\"})-[:CALL]->(m5:Method {NAME:\"deserializeWithType\", CLASSNAME:\"com.fasterxml.jackson.databind.JsonDeserializer\"})-[:ALIAS*]->(m6:Method {NAME:\"deserializeWithType\", CLASSNAME:\"com.fasterxml.jackson.databind.deser.std.UntypedObjectDeserializer$Vanilla\"})-[:CALL]->(m7:Method {NAME:\"deserializeTypedFromAny\", CLASSNAME:\"com.fasterxml.jackson.databind.jsontype.TypeDeserializer\"})-[:ALIAS*]->(m8:Method {NAME:\"deserializeTypedFromAny\", CLASSNAME:\"com.fasterxml.jackson.databind.jsontype.impl.AsArrayTypeDeserializer\"})-[:CALL]->(m9:Method {NAME:\"_deserialize\"})-[:CALL]->(m10:Method {NAME:\"deserialize\"})-[:ALIAS*]->(m11:Method {NAME:\"deserialize\", CLASSNAME:\"com.fasterxml.jackson.databind.deser.BeanDeserializer\"})-[:CALL]->(m12:Method {NAME:\"_deserializeOther\"})-[:CALL]->(m13:Method {NAME:\"deserializeFromString\", CLASSNAME:\"com.fasterxml.jackson.databind.deser.BeanDeserializerBase\"})-[:CALL]->(m14:Method {NAME:\"createFromString\", CLASSNAME:\"com.fasterxml.jackson.databind.deser.ValueInstantiator\"})-[:ALIAS*]->(m15:Method {NAME:\"createFromString\", CLASSNAME:\"com.fasterxml.jackson.databind.deser.std.StdValueInstantiator\"})-[:CALL]->(m16:Method {NAME:\"call1\", CLASSNAME:\"com.fasterxml.jackson.databind.introspect.AnnotatedWithParams\"})-[:ALIAS*]->(m17:Method {NAME:\"call1\", CLASSNAME:\"com.fasterxml.jackson.databind.introspect.AnnotatedConstructor\"})-[:CALL]->(m18:Method {NAME:\"newInstance\"}) return path")
    List<PathValue> DeserializeAll_CVE_2020_24750();


    @Query("match (source:Method) where source.NAME in $sourceName\n" +
            "match (sink:Method) where sink.NAME in $sinkName and sink.CLASSNAME in $sinkClassname\n" +
            "call apoc.algo.allSimplePaths(sink, source, \"CALL|ALIAS\", $depth) yield path\n" +
            "return path limit 100")
    List<PathValue> jacksonTwo(List<String> sourceName, List<String> sinkName, List<String> sinkClassname, int depth);
}
















