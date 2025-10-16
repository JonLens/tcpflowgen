#include "FlowUtils.h"
#include <tuple>


FlowKey::FlowKey(const std::string& ip1, uint16_t port1, const std::string& ip2, uint16_t port2) {
    std::tuple<std::string, uint16_t> endpoint1(ip1, port1);
    std::tuple<std::string, uint16_t> endpoint2(ip2, port2);
    
    if (endpoint1 < endpoint2) {
        src_ip = ip1;
        src_port = port1;
        dst_ip = ip2;
        dst_port = port2;
    } else {
        src_ip = ip2;
        src_port = port2;
        dst_ip = ip1;
        dst_port = port1;
    }
}

bool FlowKey::operator<(const FlowKey& other) const { // Compare Flows
    return std::tie(src_ip, src_port, dst_ip, dst_port) < 
           std::tie(other.src_ip, other.src_port, other.dst_ip, other.dst_port);
}

arrow::Status save_tokens_arrow(const std::vector<std::vector<int>>& tokens,
    const std::string& filepath) {
    // Use a ListBuilder where each element is itself an Int32 array.
    arrow::MemoryPool* pool = arrow::default_memory_pool();
    auto value_builder = std::make_shared<arrow::Int32Builder>(pool);
    arrow::ListBuilder list_builder(pool, value_builder);
    
    // Get the underlying Int32Builder to append the actual token values
    arrow::Int32Builder* int_builder =
        static_cast<arrow::Int32Builder*>(list_builder.value_builder());
    if (int_builder == nullptr) {
        std::cerr << "Error: Failed to get the value builder from the list builder." << std::endl;
        return arrow::Status::Invalid("Failed to get value builder");
    }
    
    // Build the list array
    for (const auto& seq : tokens) {
        // Append signifies the start of a new list element (a new sequence)
        ARROW_RETURN_NOT_OK(list_builder.Append());
        
        // Append all the integer tokens for the current sequence
        if (seq.size() > 0) {  // Add check for empty sequences
            ARROW_RETURN_NOT_OK(int_builder->AppendValues(seq.data(), seq.size()));
        }
    }
    
    // Finalize the list array
    std::shared_ptr<arrow::Array> list_array;
    ARROW_RETURN_NOT_OK(list_builder.Finish(&list_array));
    
    // Create table schema - now just one column of type list<int32>
    auto schema = arrow::schema({
        arrow::field("token_sequences", arrow::list(arrow::int32()))
    });
    
    // Create table
    auto table = arrow::Table::Make(schema, {list_array});
    
    // Write to file
    std::shared_ptr<arrow::io::FileOutputStream> outfile;
    ARROW_ASSIGN_OR_RAISE(outfile, arrow::io::FileOutputStream::Open(filepath));
    
    // Create writer and write the table
    std::shared_ptr<arrow::ipc::RecordBatchWriter> writer;
    ARROW_ASSIGN_OR_RAISE(writer, arrow::ipc::MakeFileWriter(outfile, schema));
    
    ARROW_RETURN_NOT_OK(writer->WriteTable(*table));
    ARROW_RETURN_NOT_OK(writer->Close());
    
    // Make sure to flush and close the file
    ARROW_RETURN_NOT_OK(outfile->Close());
    
    return arrow::Status::OK();
}
