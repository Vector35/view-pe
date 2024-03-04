#pragma once

#include "binaryninjaapi.h"
#include "peview.h"

#ifdef WIN32
#pragma warning(disable: 4005)
#endif


// EFI_IMAGE_DATA_DIRECTORY
struct TEImageDataDirectory {
    uint32_t virtualAddress;
    uint32_t size;
};

#define EFI_TE_IMAGE_HEADER_SIZE 40
#define EFI_TE_SECTION_HEADER_SIZE 40

// EFI_TE_IMAGE_HEADER
struct TEImageHeader {
    uint16_t magic;
    uint16_t machine;
    uint8_t numberOfSections;
    uint8_t subsystem;
    uint8_t strippedSize;
    uint32_t addressOfEntrypoint;
    uint32_t baseOfCode;
    uint64_t imageBase;
    struct TEImageDataDirectory dataDirectory[2];
};

// EFI_IMAGE_SECTION_HEADER
struct TEImageSectionHeader {
    std::string name; // 8 bytes
    union {
        uint32_t physicalAddress;
        uint32_t virtualSize;
    } Misc;
    uint32_t virtualAddress;
    uint32_t sizeOfRawData;
    uint32_t pointerToRawData;
    uint32_t pointerToRelocations;
    uint32_t pointerToLineNumbers;
    uint16_t numberOfRelocations;
    uint16_t numberOfLineNumbers;
    uint32_t characteristics;
};

namespace BinaryNinja
{
    class TEView: public BinaryView
    {
        bool m_parseOnly;
        std::vector<TEImageSectionHeader> m_sections;
        bool m_relocatable = false;
        Ref<Logger> m_logger;
        Ref<Architecture> m_arch;
        bool m_backedByDatabase;

        uint64_t m_imageBase;
        uint64_t m_entryPoint;
        bool m_is64;
        
    protected:
        virtual uint64_t PerformGetEntryPoint() const override;
        virtual bool PerformIsExecutable() const override { return true; }
        virtual BNEndianness PerformGetDefaultEndianness() const override { return LittleEndian; }
        virtual bool PerformIsRelocatable() const override { return m_relocatable; }
        virtual size_t PerformGetAddressSize() const override;

    public:
        TEView(BinaryView* data, bool parseOnly = false);
        virtual bool Init() override;
    };

    class TEViewType: public BinaryViewType
    {
		Ref<Logger> m_logger;

    public:
        TEViewType();
        virtual Ref<BinaryView> Create(BinaryView* data) override;
        virtual Ref<BinaryView> Parse(BinaryView* data) override;
        virtual bool IsTypeValidForData(BinaryView* data) override;
        virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override;
    };

    void InitTEViewType();
}