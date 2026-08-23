/*
 * Copyright (C) 2026
 * Licensed under the Apache License, Version 2.0.
 */
package com.reandroid.apkeditor.protect;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/** Converts every proto-resource AAB module through aapt2 and protects it in bundle-safe mode. */
final class AabProtector {

    private final Protector protector;
    private final ProtectorOptions options;
    private Path workDirectory;

    AabProtector(Protector protector) {
        this.protector = protector;
        this.options = protector.getOptions();
    }

    void protect() throws IOException {
        if (options.confuse_zip) {
            throw new IOException("-confuse-zip is not supported for AAB output; it produces an invalid bundle.");
        }
        workDirectory = Files.createTempDirectory("apkeditor-aab-");
        try {
            Path aapt2 = resolveAapt2();
            Path extracted = workDirectory.resolve("bundle");
            extractZip(options.inputFile.toPath(), extracted);
            if (!Files.isRegularFile(extracted.resolve("BundleConfig.pb"))) {
                throw new IOException("Not a valid AAB: BundleConfig.pb is missing.");
            }
            List<Path> modules = findResourceModules(extracted);
            if (modules.isEmpty()) {
                throw new IOException("Not a valid resource AAB: no */resources.pb module was found.");
            }
            protector.logMessage("AAB modules with resources: " + modules.size());
            int index = 0;
            for (Path module : modules) {
                protectModule(aapt2, extracted, module, index++);
            }
            deleteTree(extracted.resolve("META-INF"));
            zipDirectory(extracted, options.outputFile.toPath());
            signOutputIfConfigured();
            protector.logMessage("Saved AAB to: " + options.outputFile);
        } finally {
            if (workDirectory != null) {
                deleteTree(workDirectory);
            }
        }
    }

    private void protectModule(Path aapt2, Path bundleRoot, Path module, int index) throws IOException {
        Path stage = workDirectory.resolve("module-" + index);
        Path inputDirectory = stage.resolve("input");
        copyTree(module, inputDirectory);
        Path bundleManifest = inputDirectory.resolve("manifest/AndroidManifest.xml");
        if (!Files.isRegularFile(bundleManifest)) {
            throw new IOException("AAB module has resources.pb but no manifest: " +
                    bundleRoot.relativize(module));
        }
        Files.copy(bundleManifest, inputDirectory.resolve("AndroidManifest.xml"),
                StandardCopyOption.REPLACE_EXISTING);

        Path protoApk = stage.resolve("module-proto.apk");
        Path binaryApk = stage.resolve("module-binary.apk");
        Path protectedApk = stage.resolve("module-protected.apk");
        Path protectedProtoApk = stage.resolve("module-protected-proto.apk");
        zipDirectory(inputDirectory, protoApk);
        runAapt2(aapt2, "convert", "--output-format", "binary", "-o",
                binaryApk.toString(), protoApk.toString());
        protector.protectApk(binaryApk.toFile(), protectedApk.toFile(), true);
        runAapt2(aapt2, "convert", "--output-format", "proto", "-o",
                protectedProtoApk.toString(), protectedApk.toString());

        Path converted = stage.resolve("converted");
        extractZip(protectedProtoApk, converted);
        Path convertedManifest = converted.resolve("AndroidManifest.xml");
        if (!Files.isRegularFile(convertedManifest) ||
                !Files.isRegularFile(converted.resolve("resources.pb"))) {
            throw new IOException("aapt2 did not produce a valid proto module for " +
                    bundleRoot.relativize(module));
        }
        deleteTree(module);
        Files.move(converted, module, StandardCopyOption.REPLACE_EXISTING);
        deleteTree(module.resolve("manifest"));
        Files.createDirectories(module.resolve("manifest"));
        Files.move(module.resolve("AndroidManifest.xml"),
                module.resolve("manifest/AndroidManifest.xml"), StandardCopyOption.REPLACE_EXISTING);
        protector.logMessage("Protected AAB module: " + bundleRoot.relativize(module));
    }

    private Path resolveAapt2() throws IOException {
        if (options.aapt2 != null) {
            Path path = options.aapt2.toPath();
            if (!Files.isRegularFile(path) || !Files.isExecutable(path)) {
                throw new IOException("Invalid -aapt2 executable: " + path);
            }
            return path;
        }
        if (options.bundletool == null || !options.bundletool.isFile()) {
            throw new IOException("AAB protection requires -aapt2 <executable> or -bundletool <bundletool-all.jar>.");
        }
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String entryName;
        if (os.contains("linux")) {
            entryName = "linux/aapt2";
        } else if (os.contains("mac")) {
            entryName = "macos/aapt2";
        } else if (os.contains("win")) {
            entryName = "windows/aapt2.exe";
        } else {
            throw new IOException("Unsupported host OS for bundletool aapt2 extraction: " + os);
        }
        Path executable = workDirectory.resolve(new File(entryName).getName());
        try (ZipFile zipFile = new ZipFile(options.bundletool)) {
            ZipEntry entry = zipFile.getEntry(entryName);
            if (entry == null) {
                throw new IOException("bundletool does not contain " + entryName + ": " + options.bundletool);
            }
            try (InputStream inputStream = zipFile.getInputStream(entry);
                 OutputStream outputStream = Files.newOutputStream(executable)) {
                copy(inputStream, outputStream);
            }
        }
        executable.toFile().setExecutable(true);
        return executable;
    }

    private void signOutputIfConfigured() throws IOException {
        if (!hasSigningOption()) {
            protector.logMessage("AAB signatures were removed; output is unsigned.");
            return;
        }
        if (options.signKeystore == null || !options.signKeystore.isFile() ||
                isEmpty(options.signAlias) || isEmpty(options.signStorepassEnv)) {
            throw new IOException("AAB signing requires -sign-keystore, -sign-alias, and -sign-storepass-env.");
        }
        requireEnvironment(options.signStorepassEnv, "-sign-storepass-env");
        if (!isEmpty(options.signKeypassEnv)) {
            requireEnvironment(options.signKeypassEnv, "-sign-keypass-env");
        }
        List<String> command = new ArrayList<>();
        command.add(options.jarsigner == null ? "jarsigner" : options.jarsigner.getAbsolutePath());
        command.add("-keystore");
        command.add(options.signKeystore.getAbsolutePath());
        if (!isEmpty(options.signStoretype)) {
            command.add("-storetype");
            command.add(options.signStoretype);
        }
        command.add("-storepass:env");
        command.add(options.signStorepassEnv);
        if (!isEmpty(options.signKeypassEnv)) {
            command.add("-keypass:env");
            command.add(options.signKeypassEnv);
        }
        command.add(options.outputFile.getAbsolutePath());
        command.add(options.signAlias);
        runProcess(command, "jarsigner");
        List<String> verify = new ArrayList<>();
        verify.add(command.get(0));
        verify.add("-verify");
        verify.add(options.outputFile.getAbsolutePath());
        runProcess(verify, "jarsigner verification");
        protector.logMessage("Signed AAB with alias: " + options.signAlias);
    }

    private boolean hasSigningOption() {
        return options.signKeystore != null || !isEmpty(options.signAlias) ||
                !isEmpty(options.signStorepassEnv) || !isEmpty(options.signKeypassEnv) ||
                !isEmpty(options.signStoretype) || options.jarsigner != null;
    }
    private static boolean isEmpty(String value) {
        return value == null || value.length() == 0;
    }
    private static void requireEnvironment(String name, String option) throws IOException {
        if (isEmpty(System.getenv(name))) {
            throw new IOException(option + " references an unset or empty environment variable: " + name);
        }
    }

    private void runAapt2(Path executable, String... args) throws IOException {
        List<String> command = new ArrayList<>();
        command.add(executable.toString());
        for (String arg : args) {
            command.add(arg);
        }
        runProcess(command, "aapt2");
    }

    private static void runProcess(List<String> command, String name) throws IOException {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (output.length() < 16000) {
                    output.append(line).append('\n');
                }
            }
        }
        try {
            int code = process.waitFor();
            if (code != 0) {
                throw new IOException(name + " failed (exit " + code + "): " + output);
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while running " + name, exception);
        }
    }

    private static List<Path> findResourceModules(Path root) throws IOException {
        List<Path> modules = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(root)) {
            paths.filter(path -> path.getFileName().toString().equals("resources.pb"))
                    .sorted(Comparator.comparing(Path::toString))
                    .forEach(path -> modules.add(path.getParent()));
        }
        return modules;
    }

    private static void extractZip(Path zip, Path directory) throws IOException {
        Files.createDirectories(directory);
        try (ZipFile zipFile = new ZipFile(zip.toFile())) {
            java.util.Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                Path target = directory.resolve(entry.getName()).normalize();
                if (!target.startsWith(directory)) {
                    throw new IOException("Unsafe zip entry: " + entry.getName());
                }
                if (entry.isDirectory()) {
                    Files.createDirectories(target);
                    continue;
                }
                Files.createDirectories(target.getParent());
                try (InputStream inputStream = zipFile.getInputStream(entry);
                     OutputStream outputStream = Files.newOutputStream(target)) {
                    copy(inputStream, outputStream);
                }
            }
        }
    }

    private static void zipDirectory(Path directory, Path output) throws IOException {
        Files.createDirectories(output.getParent());
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(output))) {
            try (Stream<Path> paths = Files.walk(directory)) {
                paths.filter(Files::isRegularFile).sorted().forEach(path -> {
                    String name = directory.relativize(path).toString().replace(File.separatorChar, '/');
                    try {
                        zip.putNextEntry(new ZipEntry(name));
                        Files.copy(path, zip);
                        zip.closeEntry();
                    } catch (IOException exception) {
                        throw new ZipWriteException(exception);
                    }
                });
            }
        } catch (ZipWriteException exception) {
            throw exception.getCause();
        }
    }

    private static void copyTree(Path source, Path target) throws IOException {
        Files.walkFileTree(source, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attributes)
                    throws IOException {
                Files.createDirectories(target.resolve(source.relativize(directory)));
                return FileVisitResult.CONTINUE;
            }
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                Files.copy(file, target.resolve(source.relativize(file)),
                        StandardCopyOption.REPLACE_EXISTING);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private static void deleteTree(Path path) throws IOException {
        if (path == null || !Files.exists(path)) {
            return;
        }
        Files.walkFileTree(path, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }
            @Override
            public FileVisitResult postVisitDirectory(Path directory, IOException exception) throws IOException {
                if (exception != null) {
                    throw exception;
                }
                Files.delete(directory);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private static void copy(InputStream inputStream, OutputStream outputStream) throws IOException {
        byte[] buffer = new byte[8192];
        int read;
        while ((read = inputStream.read(buffer)) >= 0) {
            outputStream.write(buffer, 0, read);
        }
    }

    private static final class ZipWriteException extends RuntimeException {
        private ZipWriteException(IOException cause) {
            super(cause);
        }
        @Override
        public IOException getCause() {
            return (IOException) super.getCause();
        }
    }
}
