function Get-ClonedObject {

    param($DeepCopyObject)
    $memStream = [IO.MemoryStream]::new()
    $formatter = [Runtime.Serialization.Formatters.Binary.BinaryFormatter]::new()
    $formatter.Serialize($memStream, $DeepCopyObject)
    $memStream.Position = 0
    $formatter.Deserialize($memStream)
}
