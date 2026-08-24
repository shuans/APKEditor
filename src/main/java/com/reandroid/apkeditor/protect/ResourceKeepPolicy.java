/*
 * Copyright (C) 2026
 * Licensed under the Apache License, Version 2.0.
 */
package com.reandroid.apkeditor.protect;

import com.reandroid.apk.ApkModule;
import com.reandroid.apk.DexFileInputSource;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.instruction.FiveRegisterInstruction;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.OneRegisterInstruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.instruction.RegisterRangeInstruction;
import org.jf.dexlib2.iface.instruction.TwoRegisterInstruction;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.Reference;
import org.jf.dexlib2.iface.reference.StringReference;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Keeps resources whose runtime names are passed to Resources.getIdentifier. */
public final class ResourceKeepPolicy {

    private static final ResourceKeepPolicy EMPTY = new ResourceKeepPolicy();
    private static final String RESOURCES_CLASS = "Landroid/content/res/Resources;";

    private final Set<ResourceName> resources = new LinkedHashSet<>();

    private ResourceKeepPolicy() {
    }

    public static ResourceKeepPolicy empty() {
        return EMPTY;
    }

    public static ResourceKeepPolicy create(Protector protector, ApkModule module) throws IOException {
        if (!protector.getOptions().keepDynamicResources) {
            return EMPTY;
        }
        ResourceKeepPolicy result = new ResourceKeepPolicy();
        List<String> unresolved = new ArrayList<>();
        for (DexFileInputSource source : module.listDexFiles()) {
            result.scanDex(source, unresolved,
                    protector.getOptions().dynamicResourceScanPackages);
        }
        if (!unresolved.isEmpty()) {
            throw new IOException("Cannot safely protect dynamic resources. " +
                    "Unresolved Resources.getIdentifier call(s): " + join(unresolved) +
                    ". Resolve the name/type to const-string values, or narrow the scan with " +
                    "-dynamic-resource-scan-package.");
        }
        protector.logMessage("Dynamic resources kept: " + result.resources.size());
        return result;
    }

    public boolean isKeep(String type, String name) {
        if (type == null || name == null) {
            return false;
        }
        return resources.contains(new ResourceName(type, name));
    }
    private void scanDex(DexFileInputSource source, List<String> unresolved,
                         Set<String> packagePrefixes) throws IOException {
        try (InputStream inputStream = source.openStream()) {
            DexBackedDexFile dexFile = DexBackedDexFile.fromInputStream(
                    Opcodes.getDefault(), inputStream);
            for (ClassDef classDef : dexFile.getClasses()) {
                if (!isInScanScope(classDef, packagePrefixes)) {
                    continue;
                }
                for (Method method : classDef.getMethods()) {
                    scanMethod(classDef, method, unresolved);
                }
            }
        }
    }

    private void scanMethod(ClassDef classDef, Method method, List<String> unresolved) {
        MethodImplementation implementation = method.getImplementation();
        if (implementation == null) {
            return;
        }
        Map<Integer, String> strings = new HashMap<>();
        int index = 0;
        for (Instruction instruction : implementation.getInstructions()) {
            Opcode opcode = instruction.getOpcode();
            if (opcode == Opcode.CONST_STRING || opcode == Opcode.CONST_STRING_JUMBO) {
                Reference reference = ((ReferenceInstruction) instruction).getReference();
                strings.put(((OneRegisterInstruction) instruction).getRegisterA(),
                        ((StringReference) reference).getString());
            } else if (opcode.name().startsWith("MOVE_OBJECT") &&
                    instruction instanceof TwoRegisterInstruction) {
                TwoRegisterInstruction move = (TwoRegisterInstruction) instruction;
                String value = strings.get(move.getRegisterB());
                if (value == null) {
                    strings.remove(move.getRegisterA());
                } else {
                    strings.put(move.getRegisterA(), value);
                }
            } else if (isGetIdentifier(instruction)) {
                inspectGetIdentifier(classDef, method, index, instruction, strings, unresolved);
            } else if (opcode.setsRegister() && instruction instanceof OneRegisterInstruction) {
                strings.remove(((OneRegisterInstruction) instruction).getRegisterA());
            }
            index++;
        }
    }

    private void inspectGetIdentifier(ClassDef classDef, Method method, int index,
                                      Instruction instruction, Map<Integer, String> strings,
                                      List<String> unresolved) {
        int[] registers = getInvokeRegisters(instruction);
        if (registers == null || registers.length != 4) {
            unresolved.add(location(classDef, method, index) + " has an unsupported invoke form");
            return;
        }
        String packageName = strings.get(registers[3]);
        if ("android".equals(packageName)) {
            return;
        }
        String name = strings.get(registers[1]);
        String type = strings.get(registers[2]);
        if (name == null || type == null) {
            unresolved.add(location(classDef, method, index));
            return;
        }
        resources.add(new ResourceName(type, name));
    }

    private static boolean isInScanScope(ClassDef classDef, Set<String> packagePrefixes) {
        if (packagePrefixes.isEmpty()) {
            return true;
        }
        String className = classDef.getType();
        for (String prefix : packagePrefixes) {
            String descriptorPrefix = "L" + prefix.replace('.', '/').replace('\\', '/');
            if (!descriptorPrefix.endsWith("/")) {
                descriptorPrefix += "/";
            }
            if (className.startsWith(descriptorPrefix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isGetIdentifier(Instruction instruction) {
        if (!(instruction instanceof ReferenceInstruction)) {
            return false;
        }
        Reference reference = ((ReferenceInstruction) instruction).getReference();
        if (!(reference instanceof MethodReference)) {
            return false;
        }
        MethodReference method = (MethodReference) reference;
        return RESOURCES_CLASS.equals(method.getDefiningClass()) &&
                "getIdentifier".equals(method.getName()) &&
                method.getParameterTypes().size() == 3;
    }

    private static int[] getInvokeRegisters(Instruction instruction) {
        if (instruction instanceof FiveRegisterInstruction) {
            FiveRegisterInstruction invoke = (FiveRegisterInstruction) instruction;
            if (invoke.getRegisterCount() != 4) {
                return null;
            }
            return new int[]{invoke.getRegisterC(), invoke.getRegisterD(),
                    invoke.getRegisterE(), invoke.getRegisterF()};
        }
        if (instruction instanceof RegisterRangeInstruction) {
            RegisterRangeInstruction invoke = (RegisterRangeInstruction) instruction;
            if (invoke.getRegisterCount() != 4) {
                return null;
            }
            int start = invoke.getStartRegister();
            return new int[]{start, start + 1, start + 2, start + 3};
        }
        return null;
    }

    private static String location(ClassDef classDef, Method method, int index) {
        return classDef.getType() + "->" + method.getName() + "#" + index;
    }
    private static String join(List<String> values) {
        int limit = Math.min(values.size(), 12);
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < limit; i++) {
            if (i != 0) {
                builder.append(", ");
            }
            builder.append(values.get(i));
        }
        if (values.size() > limit) {
            builder.append(" (and ").append(values.size() - limit).append(" more)");
        }
        return builder.toString();
    }

    private static final class ResourceName {
        private final String type;
        private final String name;

        private ResourceName(String type, String name) {
            this.type = type;
            this.name = name;
        }
        @Override
        public boolean equals(Object object) {
            if (this == object) {
                return true;
            }
            if (!(object instanceof ResourceName)) {
                return false;
            }
            ResourceName other = (ResourceName) object;
            return type.equals(other.type) && name.equals(other.name);
        }
        @Override
        public int hashCode() {
            return 31 * type.hashCode() + name.hashCode();
        }
    }
}
