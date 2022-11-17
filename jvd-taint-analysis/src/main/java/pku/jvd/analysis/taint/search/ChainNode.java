package pku.jvd.analysis.taint.search;

import lombok.Data;
import pku.jvd.analysis.taint.abstraction.FlowAbstraction;

@Data
public class ChainNode {
    private FlowAbstraction node;

    public ChainNode(FlowAbstraction node) {
        this.node = node;
    }

    public ChainNode() {

    }

    public FlowAbstraction getNode() {
        return node;
    }

    public void setNode(FlowAbstraction node) {
        this.node = node;
    }

    public String toString() {
        return "{" + node.getLocationName() + ":" + node.getSource() + "}";
    }
}