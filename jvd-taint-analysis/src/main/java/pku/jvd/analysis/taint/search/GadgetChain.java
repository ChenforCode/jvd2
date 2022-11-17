package pku.jvd.analysis.taint.search;


import lombok.Data;
import pku.jvd.analysis.taint.abstraction.FlowAbstraction;

import java.util.ArrayList;
import java.util.List;

@Data
public class GadgetChain {
    FlowAbstraction source;
    List<ChainNode> chain = new ArrayList<>();

    public GadgetChain(List<ChainNode> chain) {
        this.chain = chain;
    }

    public GadgetChain() {

    }

    public List<ChainNode> newChain(List<ChainNode> chain, ChainNode newNode) {
        List<ChainNode> newChain = new ArrayList<>(chain);
        newChain.add(newNode);
        return newChain;
    }

    public FlowAbstraction getSource() {
        return source;
    }

    public void setSource(FlowAbstraction source) {
        this.source = source;
    }

    public List<ChainNode> getChain() {
        return chain;
    }

    public void setChain(List<ChainNode> chain) {
        this.chain = chain;
    }

    @Override
    public String toString() {
        StringBuilder res = new StringBuilder();
        if (chain == null || chain.size() == 0) {
            return res.toString();
        }
        res.append("Source: " + "{").append(source.getLocationName()).append(":").append(source.getSource()).append("}\n");
        for (ChainNode chainNode : chain) {
            res.append("    -> " + chainNode.toString() + "\n");
        }
        res.append("\n");
        return res.toString();
    }
}
