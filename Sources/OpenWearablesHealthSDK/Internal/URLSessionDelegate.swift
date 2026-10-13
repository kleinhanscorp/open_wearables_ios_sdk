import Foundation

extension OpenWearablesHealthSDK {

    // MARK: - URLSession delegate
    public func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard let desc = task.taskDescription else { return }
        let parts = desc.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
        let itemPath = parts.count > 0 ? parts[0] : ""
        let payloadPath = parts.count > 1 ? parts[1] : ""
        let anchorPath = parts.count > 2 ? parts[2] : ""

        OpenWearablesHealthSdkKeychain.connectionLock.lock()
        defer { OpenWearablesHealthSdkKeychain.connectionLock.unlock() }
        guard let itemData = try? Data(contentsOf: URL(fileURLWithPath: itemPath)),
              let initiatingItem = try? JSONDecoder().decode(OutboxItem.self, from: itemData),
              initiatingItem.userKey == userKey(), initiatingItem.connectionGeneration == connectionGeneration() else { return }
        let owner = OpenWearablesHealthSdkKeychain.connectionOwner()

        if backgroundDataBuffer[task.taskIdentifier] != nil {
            backgroundDataBuffer.removeValue(forKey: task.taskIdentifier)
        }

        if let error = error {
            let nsError = error as NSError
            if nsError.code != NSURLErrorCancelled {
                NSLog("[OpenWearablesHealthSDK] background upload failed: \(error.localizedDescription) - will retry later")
            }
            return
        }

        let statusCode = (task.response as? HTTPURLResponse)?.statusCode ?? 0

        if (200...299).contains(statusCode) {
            if !itemPath.isEmpty,
               let itemData = try? Data(contentsOf: URL(fileURLWithPath: itemPath)),
               let item = try? JSONDecoder().decode(OutboxItem.self, from: itemData) {
                // Saves anchors (combined & per-type), marks fullDone when applicable,
                // and removes the item + anchor files.
                handleSuccessfulUpload(
                    itemPath: itemPath,
                    anchorPath: anchorPath.isEmpty ? nil : anchorPath,
                    wasFullExport: item.wasFullExport ?? false
                )
            }
            if !payloadPath.isEmpty { try? FileManager.default.removeItem(atPath: payloadPath) }
            return
        }

        if statusCode == 401 {
            // Keep the files - after a successful token refresh the retry pass
            // picks them up again.
            if isApiKeyAuth {
                self.logMessage("Background 401 with API key - emitting auth error")
                DispatchQueue.main.async { [weak self] in
                    guard OpenWearablesHealthSdkKeychain.isCurrent(owner) else { return }
                    self?.emitAuthError(statusCode: 401)
                }
            } else {
                self.attemptTokenRefresh { [weak self] result in
                    guard let self = self else { return }
                    guard OpenWearablesHealthSdkKeychain.isCurrent(owner) else { return }
                    switch result {
                    case .success:
                        self.logMessage("Token refreshed after background 401 - retrying outbox...")
                        self.retryOutboxIfPossible()
                    case .authFailure:
                        DispatchQueue.main.async { [weak self] in
                            guard OpenWearablesHealthSdkKeychain.isCurrent(owner) else { return }
                    self?.emitAuthError(statusCode: 401)
                        }
                    case .networkError:
                        self.logMessage("Token refresh failed (network) after background 401 - will retry later")
                    }
                }
            }
            return
        }

        recordUploadRejection(itemPath: itemPath, status: statusCode)

    }

    public func urlSessionDidFinishEvents(forBackgroundURLSession session: URLSession) {
        if let handler = OpenWearablesHealthSDK.bgCompletionHandler {
            OpenWearablesHealthSDK.bgCompletionHandler = nil
            handler()
        }
    }
    
    public func urlSession(_ session: URLSession, task: URLSessionTask, didSendBodyData bytesSent: Int64, totalBytesSent: Int64, totalBytesExpectedToSend: Int64) {
        let progress = Double(totalBytesSent) / Double(totalBytesExpectedToSend) * 100
        if Int(progress) % 20 == 0 || progress > 99 {
            NSLog("[OpenWearablesHealthSDK] Upload progress: \(String(format: "%.1f", progress))%% (\(totalBytesSent)/\(totalBytesExpectedToSend) bytes)")
        }
    }
    
    public func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        completionHandler(.allow)
    }

    public func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        if backgroundDataBuffer[dataTask.taskIdentifier] == nil {
            backgroundDataBuffer[dataTask.taskIdentifier] = data
        } else {
            backgroundDataBuffer[dataTask.taskIdentifier]?.append(data)
        }
    }
}
