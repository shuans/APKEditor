/*
  *  Copyright (C) 2022 github.com/REAndroid
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
  *  You may obtain a copy of the License at
  *
  *      http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
package com.reandroid.apkeditor.protect;

import com.reandroid.apkeditor.CommandExecutor;
import com.reandroid.apkeditor.Util;
import com.reandroid.apk.*;

import java.io.File;
import java.io.IOException;

public class Protector extends CommandExecutor<ProtectorOptions> {

    private ApkModule mApkModule;
    private ResourceKeepPolicy resourceKeepPolicy = ResourceKeepPolicy.empty();
    private boolean aabSafeMode;

    public Protector(ProtectorOptions options) {
        super(options, "[PROTECT] ");
    }

    public ApkModule getApkModule() {
        return this.mApkModule;
    }

    public void setApkModule(ApkModule apkModule) {
        this.mApkModule = apkModule;
    }
    public ResourceKeepPolicy getResourceKeepPolicy() {
        return resourceKeepPolicy;
    }
    public boolean isAabSafeMode() {
        return aabSafeMode;
    }

    @Override
    public ProtectorOptions getOptions() {
        return super.getOptions();
    }

    @Override
    public void runCommand() throws IOException {
        ProtectorOptions options = getOptions();
        delete(options.outputFile);
        if (isAab(options.inputFile)) {
            new AabProtector(this).protect();
            return;
        }
        protectApk(options.inputFile, options.outputFile, false);
    }

    void protectApk(File inputFile, File outputFile, boolean aabSafeMode) throws IOException {
        ProtectorOptions options = getOptions();
        this.aabSafeMode = aabSafeMode;
        ApkModule module = ApkModule.loadApkFile(this, inputFile);
        try {
            module.setLoadDefaultFramework(false);
            String protect = Util.isProtected(module);
            if(protect != null){
                throw new IOException(inputFile.getAbsolutePath() + ": " + protect);
            }
            setApkModule(module);
            resourceKeepPolicy = ResourceKeepPolicy.create(this, module);
            if (aabSafeMode) {
                logMessage("AAB safe mode: skipping manifest, directory, and table chunk protection");
            } else {
                new ManifestConfuser(this).confuse();
                new DirectoryConfuser(this).confuse();
            }
            new FileNameConfuser(this).confuse();
            if (!aabSafeMode) {
                new TableConfuser(this).confuse();
            }
            new DexConfuser(this).confuse();
            module.getTableBlock().refresh();
            logMessage("Writing apk ...");
            if (options.confuse_zip) {
                logMessage("Confusing zip structure ...");
                new ProtectedFileWriter(module, outputFile).write();
            } else {
                module.writeApk(outputFile);
            }
            logMessage("Saved to: " + outputFile);
        } finally {
            resourceKeepPolicy = ResourceKeepPolicy.empty();
            setApkModule(null);
            this.aabSafeMode = false;
            module.close();
        }
    }
    private static boolean isAab(File file) {
        return file.getName().toLowerCase().endsWith(".aab");
    }
}
